package keeper

// Running sops over the managed files.

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// DecryptAll decrypts every managed file. Per-file failures are returned as
// errors rather than aborting, so one broken file does not blank the value
// set.
//
// The third return is the refs two files define with different values. One
// value wins and the other leaves the value set entirely, so it is injected by
// nothing and redacted by nothing: the same consequence as a value below
// [secret] min_length, and reported the same way rather than left to a daemon
// log line. Two files holding the same value are not this, nothing being lost
// when the one that does not win is byte for byte the one that does.
func DecryptAll(secrets config.SecretConfig, keys *KeyHolder) (map[string]string, []string, map[string]string) {
	values := map[string]string{}
	// Every file that defined each ref, and whether any two of them disagreed
	// about its value.
	definedIn := map[string][]string{}
	disagreed := map[string]bool{}
	paths, errors, _ := Resolve(secrets.Patterns)

	// Fixed rather than inherited: argv[0] is a bare "sops", so the PATH in it
	// is what resolves it, and the binary that decrypts every managed file must
	// not depend on the environment the keeper unit was started with.
	env := config.SopsEnv()
	// The path, never the material: SOPS_AGE_KEY would put the key in the child's
	// environment block, visible in /proc/<pid>/environ.
	if path := keys.Path(); path != "" {
		env = append(env, "SOPS_AGE_KEY_FILE="+path)
	}

	// One budget across the whole set as well as one per file: otherwise the reply
	// is bounded only by len(paths) * decryptTimeout, which no caller knows in
	// advance, and a large enough store would time out on the broker's side while
	// this was still working. Files past the budget report as failures.
	overall, cancelAll := context.WithTimeout(context.Background(), decryptBudget)
	defer cancelAll()

	for _, path := range paths {
		argv := make([]string, 0, len(secrets.DecryptCommand))
		for _, a := range secrets.DecryptCommand {
			argv = append(argv, strings.ReplaceAll(a, "{file}", path))
		}
		if len(argv) == 0 {
			errors = append(errors, path+": [secret] decrypt_command is empty")
			continue
		}

		ctx, cancel := context.WithTimeout(overall, decryptTimeout)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = env
		stdout, err := cmd.Output()
		cancel()

		if err != nil {
			if exitErr, ok := goerrors.AsType[*exec.ExitError](err); ok {
				errors = append(errors, keys.Scrub(fmt.Sprintf(
					"%s: decrypt failed (%d): %s", path, exitErr.ExitCode(),
					firstLine(string(exitErr.Stderr)))))
			} else {
				errors = append(errors, keys.Scrub(fmt.Sprintf(
					"%s: running %s failed: %v", path, argv[0], err)))
			}
			continue
		}

		var tree any
		if err := json.Unmarshal(stdout, &tree); err != nil {
			errors = append(errors, fmt.Sprintf("%s: decrypted output is not JSON: %v", path, err))
			continue
		}
		for ref, value := range Flatten(tree) {
			// Only a ref two files disagree about is shadowed. Two files holding the
			// same value lose nothing: the one that does not win is byte for byte
			// the one that does, so it is in the redactor and injected by the same
			// ref, and reporting it would fail a converge on a host with nothing
			// wrong with it.
			if existing, ok := values[ref]; ok && existing != value {
				log.Printf("secret ref %s defined more than once; last wins", ref)
				disagreed[ref] = true
			}
			definedIn[ref] = append(definedIn[ref], path)
			values[ref] = value
		}
	}
	// Named by the files rather than by a count: the repair is to take the ref
	// out of one of them, so the operator needs to know which two.
	shadowed := map[string]string{}
	for ref := range disagreed {
		// Every file that defines it, not only the two that differed: the repair is
		// to take the ref out of one of them, so the operator needs the whole list.
		shadowed[ref] = "defined in " + strings.Join(definedIn[ref], " and ") +
			", and they do not all hold the same value; the last one read wins and " +
			"the value it displaced is in no redactor"
	}
	return values, errors, shadowed
}

// firstLine is the line of a decrypt failure the operator is shown, and it goes
// into `faramir status`, `doctor` and the refusal a brokered command gets.
//
// The first rather than the last: a program's error summary is conventionally
// its opening line, and the closing one is often the tail of an explanation.
// sops ends "In order for SOPS to recover the file, at least one key has to be
// successful, but none were.", so the last line reached the operator as the
// fragment "but none were." and said nothing about which file or why.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	for line := range strings.SplitSeq(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return s
}
