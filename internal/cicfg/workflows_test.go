package cicfg_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type workflow struct {
	On   map[string]yaml.Node `yaml:"on"`
	Jobs map[string]job       `yaml:"jobs"`
}

type job struct {
	Name     string               `yaml:"name"`
	Needs    yaml.Node            `yaml:"needs"`
	If       string               `yaml:"if"`
	Uses     string               `yaml:"uses"`
	With     map[string]yaml.Node `yaml:"with"`
	Env      map[string]string    `yaml:"env"`
	Steps    []step               `yaml:"steps"`
	Strategy struct {
		Matrix map[string]yaml.Node `yaml:"matrix"`
	} `yaml:"strategy"`
}

type step struct {
	Uses string               `yaml:"uses"`
	Run  string               `yaml:"run"`
	With map[string]yaml.Node `yaml:"with"`
	Env  map[string]string    `yaml:"env"`
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var result workflow
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func dependencies(t *testing.T, subject job) []string {
	t.Helper()
	if subject.Needs.Kind == yaml.ScalarNode {
		return []string{subject.Needs.Value}
	}
	var result []string
	if subject.Needs.Kind != 0 {
		if err := subject.Needs.Decode(&result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func script(subject job) string {
	var commands []string
	for _, command := range subject.Steps {
		commands = append(commands, command.Run)
	}
	return strings.Join(commands, "\n")
}

func runScript(environment []string, subject string) error {
	command := exec.Command("/bin/sh", "-ec", subject)
	command.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=/tmp"}, environment...)
	return command.Run()
}

func requiredJobs(t *testing.T, subject workflow) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, name := range []string{"AI attributions", "Test", "Lint", "Build", "E2E"} {
		for id, candidate := range subject.Jobs {
			if candidate.Name == name && len(candidate.Strategy.Matrix) == 0 && candidate.Uses == "" {
				if result[name] != "" {
					t.Fatalf("more than one direct check named %s", name)
				}
				result[name] = id
			}
		}
		if result[name] == "" {
			t.Fatalf("missing required check %s", name)
		}
	}
	return result
}

func TestValidationHasOneEventEntrypointWithEveryRequiredCheck(t *testing.T) {
	validation := readWorkflow(t, "test.yml")
	for _, event := range []string{"push", "pull_request", "workflow_dispatch"} {
		if _, exists := validation.On[event]; !exists {
			t.Errorf("missing validation event %s", event)
		}
	}
	var push struct {
		Branches []string `yaml:"branches"`
		Tags     []string `yaml:"tags"`
	}
	pushEvent := validation.On["push"]
	if err := pushEvent.Decode(&push); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(push.Branches, "**") || !slices.Contains(push.Tags, "v[0-9]+.[0-9]+.[0-9]+") {
		t.Errorf("validation must admit branch pushes and version tags: %+v", push)
	}
	requiredJobs(t, validation)
	for _, name := range []string{"release.yml", "ai-attributions.yml"} {
		helper := readWorkflow(t, name)
		if len(helper.On) != 1 {
			t.Errorf("%s has an independent event entrypoint: %v", name, helper.On)
		}
		if _, exists := helper.On["workflow_call"]; !exists {
			t.Errorf("%s is not a reusable helper", name)
		}
	}
}

func TestChecksAndTagPublishingUseTheIsolatedMakeTargets(t *testing.T) {
	validation := readWorkflow(t, "test.yml")
	for _, check := range []struct {
		id, target string
	}{{"test", "make test-go"}, {"lint", "make lint"}} {
		if got := strings.TrimSpace(script(validation.Jobs[check.id])); got != check.target {
			t.Errorf("%s bypasses the shared check target: %q", check.id, got)
		}
	}
	release := readWorkflow(t, "release.yml")
	found := false
	for _, command := range release.Jobs["goreleaser"].Steps {
		if strings.HasPrefix(command.Uses, "actions/checkout@") &&
			(command.With["persist-credentials"].Value != "false" || command.With["fetch-depth"].Value != "0") {
			t.Error("tag compiler requires full credential-free source history")
		}
		if strings.HasPrefix(command.Uses, "goreleaser/goreleaser-action@") {
			t.Error("tag publisher compiles outside the isolated Make target")
		}
		found = found || command.Run == "make release"
	}
	if !found {
		t.Error("tag publisher does not use the isolated release target")
	}
}

func TestPublicationRequiresEveryCheckAndRejectsAnotherSourceRevision(t *testing.T) {
	validation := readWorkflow(t, "test.yml")
	required := requiredJobs(t, validation)
	publisher := validation.Jobs["publish"]
	if publisher.Uses != "./.github/workflows/release.yml" || publisher.With["source_sha"].Value != "${{ github.sha }}" {
		t.Fatal("publication does not use the current revision and release helper")
	}
	for name, id := range required {
		if !slices.Contains(dependencies(t, publisher), id) {
			t.Errorf("publication does not require %s", name)
		}
	}
	const admission = "github.event_name == 'push' && (startsWith(github.ref, 'refs/tags/v') || github.ref == 'refs/heads/main')"
	if publisher.If != admission {
		t.Errorf("publication admission = %q", publisher.If)
	}
	release := readWorkflow(t, "release.yml")
	guard := release.Jobs["source"]
	if len(guard.Steps) != 1 || guard.Steps[0].Env["SOURCE_SHA"] != "${{ inputs.source_sha }}" ||
		guard.Steps[0].Env["EVENT_SHA"] != "${{ github.sha }}" {
		t.Fatal("release guard does not compare its input to the event revision")
	}
	for _, source := range []string{"event-revision", "another-revision"} {
		err := runScript([]string{"SOURCE_SHA=" + source, "EVENT_SHA=event-revision"}, script(guard))
		if (err == nil) != (source == "event-revision") {
			t.Errorf("source %q produced %v", source, err)
		}
	}
	for id, publisher := range release.Jobs {
		if id == "source" {
			continue
		}
		if !slices.Contains(dependencies(t, publisher), "source") {
			t.Errorf("%s can publish without the revision guard", id)
		}
		for _, command := range publisher.Steps {
			if strings.HasPrefix(command.Uses, "actions/checkout@") && command.With["ref"].Value != "${{ inputs.source_sha }}" {
				t.Errorf("%s checks out a revision other than the validated source", id)
			}
			if strings.HasPrefix(command.Uses, "actions/download-artifact@") {
				for _, key := range []string{"run-id", "repository", "github-token"} {
					if _, exists := command.With[key]; exists {
						t.Errorf("%s can download artifacts outside this validation run", id)
					}
				}
			}
		}
	}
}

func TestRequiredAggregatesFailForEveryUnsuccessfulDependency(t *testing.T) {
	validation := readWorkflow(t, "test.yml")
	required := requiredJobs(t, validation)
	for _, name := range []string{"AI attributions", "Build", "E2E"} {
		t.Run(name, func(t *testing.T) {
			aggregate := validation.Jobs[required[name]]
			if aggregate.If != "always()" {
				t.Fatal("required aggregate can be skipped instead of reporting a failure")
			}
			needs := dependencies(t, aggregate)
			if len(needs) == 0 {
				t.Fatal("aggregate has no dependencies")
			}
			for _, failed := range append([]string{""}, needs...) {
				for _, result := range []string{"failure", "cancelled", "skipped"} {
					command := script(aggregate)
					for _, dependency := range needs {
						status := "success"
						if dependency == failed {
							status = result
						}
						command = strings.ReplaceAll(command, "${{ needs."+dependency+".result }}", status)
					}
					err := runScript(nil, command)
					if (err == nil) != (failed == "") {
						t.Errorf("dependency %q with result %s produced %v", failed, result, err)
					}
				}
			}
		})
	}
}

func TestBothSudoArrangementsConsumeTheSamePreparedRevision(t *testing.T) {
	validation := readWorkflow(t, "test.yml")
	consumer := validation.Jobs["e2e"]
	var arrangements []string
	sudoMatrix := consumer.Strategy.Matrix["sudo"]
	if err := sudoMatrix.Decode(&arrangements); err != nil {
		t.Fatal(err)
	}
	if len(arrangements) != 2 || !slices.Contains(arrangements, "sudo") || !slices.Contains(arrangements, "sudo-rs") {
		t.Errorf("incomplete sudo coverage: %v", arrangements)
	}
	if !slices.Contains(dependencies(t, consumer), "prepare-e2e") || consumer.Env["E2E_PREBUILT"] != "1" {
		t.Fatal("arrangements can rebuild instead of consuming the prepared binaries")
	}
	const artifact = "e2e-binaries-${{ github.sha }}"
	for _, tc := range []struct {
		job    job
		action string
	}{
		{validation.Jobs["prepare-e2e"], "actions/upload-artifact@"},
		{consumer, "actions/download-artifact@"},
	} {
		found := false
		for _, command := range tc.job.Steps {
			if strings.HasPrefix(command.Uses, tc.action) {
				found = true
				if command.With["name"].Value != artifact {
					t.Error("arrangements do not consume the same revision-scoped binary artifact")
				}
			}
			if strings.HasPrefix(command.Uses, "actions/checkout@") && command.With["ref"].Value != "${{ github.sha }}" {
				t.Error("binary producer or consumer checks out a different revision")
			}
		}
		if !found {
			t.Errorf("missing %s step", tc.action)
		}
	}
}
