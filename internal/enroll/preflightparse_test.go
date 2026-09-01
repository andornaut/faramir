package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// The share walks the tree chowning and chmodding every file in it and nothing
// undoes that, so a refusal that arrives at the write leaves the client group
// holding read and write on a tree with no hook registered in it. An agent
// config faramir cannot parse is one such refusal: the merge writes its keys
// into the operator's file and will not replace a file it cannot read.
func TestAnUnparsableAgentConfigIsRefusedBeforeTheShare(t *testing.T) {
	dir := t.TempDir()
	targets, err := agentcfg.Resolve([]string{"claude"}, agentcfg.ScopeTree, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	var merged string
	for _, file := range targets[0].Files {
		if file.Merge {
			merged = file.Path
			break
		}
	}
	if merged == "" {
		t.Fatal("claude enrols no file faramir merges into")
	}
	path := filepath.Join(dir, merged)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &project{opts: Options{Dir: dir}, targets: targets, uid: hostfs.Keep, gid: hostfs.Keep}
	err = p.refuseUnparsableAgentConfig()
	if err == nil {
		t.Fatal("an unparseable agent config was accepted")
	}
	// The operator has to know which file, and that the tree is as they left it.
	for _, want := range []string{merged, "not shared"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// The ordinary file, and the absent one: neither is a refusal, or an
	// enrolment could not write the first configuration into a tree.
	if err := os.WriteFile(path, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.refuseUnparsableAgentConfig(); err != nil {
		t.Errorf("a file that parses was refused: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := p.refuseUnparsableAgentConfig(); err != nil {
		t.Errorf("a tree with no agent config yet was refused: %v", err)
	}
}
