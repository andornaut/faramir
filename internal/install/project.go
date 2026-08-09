package install

// Enrolling one project, as against provisioning the host.  `init` runs once
// per machine; this runs once per tree.  That is also what makes the working
// directory safe to default to here and unsafe there.

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/version"
)

// Markers around the instructions block, so a second run replaces what the
// first wrote instead of appending a duplicate.
const (
	snippetBegin = "<!-- BEGIN faramir: credentials -->"
	snippetEnd   = "<!-- END faramir: credentials -->"
)

// agentInstructionFiles are the names an agent reads, most specific first; the
// first is created when there is none.
var agentInstructionFiles = []string{"AGENTS.md", "CLAUDE.md"}

// ProjectOptions is one enrolment.
type ProjectOptions struct {
	// Dir is the tree to enrol.  Defaults to the working directory.
	Dir string
	// Operator owns the tree and keeps owning it; this grants group access for
	// the executor's uid.
	Operator string
	// ConfigDir is where the client group is learned.  A flag could disagree
	// with what the sockets admit, leaving a tree the executor cannot enter.
	ConfigDir string
	// Group overrides the group read from the config.  For a host whose config
	// is not readable, not for ordinary use.
	Group string
	// Hook registers the PreToolUse hook in the project's agent settings, which
	// redacts the output of everything the agent runs there.  It auto-approves
	// Bash for the project: a rewritten command matches no permission rule, so
	// the hook's deny list is what refuses one.
	Hook bool
	// Agents names which coding agents to enrol; empty means Claude Code.
	// Named rather than detected, enrolling costing something on some agents.
	// What a tree happens to carry is reported instead.
	Agents []string
	DryRun bool
	Log    func(string)
}

// ProjectReport is one enrolment's outcome.
type ProjectReport struct {
	Version  string   `json:"version"`
	Dir      string   `json:"dir"`
	Group    string   `json:"group"`
	Changed  bool     `json:"changed"`
	DryRun   bool     `json:"dry_run,omitempty"`
	Steps    []Step   `json:"steps"`
	Warnings []string `json:"warnings,omitempty"`
}

// Project enrols one tree: the group and modes that let a brokered command run
// there, and the agent configuration that makes the broker worth using.
func Project(opts ProjectOptions) (ProjectReport, error) {
	if opts.Dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return ProjectReport{}, err
		}
		opts.Dir = cwd
	}
	named := opts.Dir
	info, err := os.Stat(named)
	if err != nil || !info.IsDir() {
		return ProjectReport{}, fmt.Errorf("no directory at %s", named)
	}
	// Symlinks out before anything is decided: sharing follows a link with its
	// chmod and chown and not with its walk.  See sharetree.Resolve.
	dir, err := sharetree.Resolve(named)
	if err != nil {
		return ProjectReport{}, fmt.Errorf("resolving %s: %w", named, err)
	}
	opts.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}
	if opts.Operator == "" || opts.Operator == "root" {
		return ProjectReport{}, fmt.Errorf("name the account that works in %s: pass "+
			"--operator, or run through sudo so SUDO_USER carries it. The tree "+
			"belongs to somebody, and root here would chown a checkout away from "+
			"its owner", dir)
	}
	if os.Geteuid() != 0 && !opts.DryRun {
		return ProjectReport{}, fmt.Errorf("faramir init-project must run as root: it " +
			"changes group ownership and modes on directories you do not own")
	}
	if err := refuseOversharing(dir, opts.Operator); err != nil {
		return ProjectReport{}, err
	}

	targets, err := resolveAgents(opts.Agents)
	if err != nil {
		return ProjectReport{}, err
	}
	run := &project{opts: opts, fs: fsys{dryRun: opts.DryRun}, targets: targets}
	run.report = ProjectReport{Version: version.Version, Dir: dir, DryRun: opts.DryRun}
	// The tree being changed is not the one that was named.
	if dir != named {
		run.warn("%s resolves to %s, which is the tree being enrolled", named, dir)
	}
	if err := run.resolveGroup(); err != nil {
		return run.report, err
	}
	for _, step := range []func() error{
		run.shareTree,
		run.agentConfig,
		run.instructions,
	} {
		if err := step(); err != nil {
			return run.report, err
		}
	}
	return run.report, nil
}

// refuseOversharing stops an enrolment that would share far more than a
// project.  Sharing grants the client group read and write on every file in the
// tree, and faramir-exec is in that group: for a home that carries ~/.ssh,
// ~/.config/sops/age/keys.txt, and group write on the shell configuration that
// decides what the operator's next login runs.
//
// Refused rather than warned about, the walk not being reversible.
func refuseOversharing(dir, operator string) error {
	tooBig := func(what string) error {
		return fmt.Errorf("refusing to enrol %s: it is %s. Enrolling a tree gives the "+
			"client group read and write on every file in it, and a home carries "+
			"~/.ssh and the age key under ~/.config/sops, which decrypts the same "+
			"store. Name the project directory instead", dir, what)
	}
	switch dir {
	case "/":
		return tooBig("the root of the filesystem")
	case "/home":
		return tooBig("every home on this host")
	}
	if home := homeOf(dir); home == dir {
		return tooBig("a home directory")
	}
	// The account's own home as passwd records it, which catches one outside
	// /home and /root.  Resolved, because dir is.  An unknown account fails
	// later in shareTree, with the error that names it.
	if entry, err := user.Lookup(operator); err == nil && entry.HomeDir != "" {
		home, err := sharetree.Resolve(entry.HomeDir)
		if err != nil {
			home = filepath.Clean(entry.HomeDir)
		}
		if home == dir {
			return tooBig(operator + "'s home directory")
		}
		if encloses(dir, home) {
			return tooBig("above " + operator + "'s home directory")
		}
	}
	return nil
}

// encloses compares path elements, so /home/andornaut2 is not inside
// /home/andornaut.
func encloses(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type project struct {
	opts   ProjectOptions
	fs     fsys
	report ProjectReport
	uid    int
	gid    int
	// Before any step runs, so an unknown name stops the run before the tree's
	// ownership changes.
	targets []*agentTarget
}

func (p *project) step(name string, changed bool, detail string) {
	p.report.Steps = append(p.report.Steps, Step{Name: name, Changed: changed, Detail: detail})
	if changed {
		p.report.Changed = true
	}
	if p.opts.Log == nil {
		return
	}
	mark := "ok"
	if changed {
		mark = "changed"
	}
	line := fmt.Sprintf("%-9s %s", mark, name)
	if detail != "" {
		line += ": " + detail
	}
	p.opts.Log(line)
}

func (p *project) warn(format string, args ...any) {
	p.report.Warnings = append(p.report.Warnings, fmt.Sprintf(format, args...))
}

// resolveGroup reads the shared group out of the installed config.
// allowed_groups is what the broker socket admits, so it is the only value that
// makes a shared tree usable; a flag would leave every mode right and the
// executor still unable to enter.
func (p *project) resolveGroup() error {
	if p.opts.Group != "" {
		p.report.Group = p.opts.Group
		return nil
	}
	configFile := filepath.Join(p.opts.ConfigDir, "config.toml")
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("cannot read the client group from %s: %w\n"+
			"Run faramir init first, pass --config-dir if the config is elsewhere, "+
			"or pass --client-group to name it directly", configFile, err)
	}
	if len(cfg.Server.AllowedGroups) == 0 {
		return fmt.Errorf("%s admits no group, so a shared tree would reach nothing. "+
			"Set allowed_groups", configFile)
	}
	// The first, when there are several: a tree has one group.
	p.report.Group = cfg.Server.AllowedGroups[0]
	if len(cfg.Server.AllowedGroups) > 1 {
		p.warn("%s admits %s; this tree is given %s, which is the first",
			configFile, strings.Join(cfg.Server.AllowedGroups, ", "), p.report.Group)
	}
	return nil
}

func (p *project) shareTree() error {
	if p.opts.DryRun {
		p.step("share tree", false, fmt.Sprintf("%s with group %s",
			p.opts.Dir, p.report.Group))
		return nil
	}
	uid, err := lookupUser(p.opts.Operator)
	if err != nil {
		return err
	}
	gid, err := lookupGroup(p.report.Group)
	if err != nil {
		return err
	}
	p.uid, p.gid = uid, gid
	if err := sharetree.Share(sharetree.Options{
		Dir: p.opts.Dir, Operator: p.opts.Operator, Group: p.report.Group,
	}); err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	// The executor runs under ProtectSystem=strict with /home as its only
	// writable tree, so a tree outside it takes the group and then refuses every
	// write with EROFS.
	if homeOf(p.opts.Dir) == "" {
		p.warn("%s is outside /home, which is the only tree faramir-exec may write. "+
			"A brokered command can enter it and still gets EROFS on every write. "+
			"Add a drop-in extending ReadWritePaths= on faramir-exec.service",
			p.opts.Dir)
	}
	// Reported as no change: after the first run it re-applies what is already
	// there.
	p.step("share tree", false, fmt.Sprintf("%s with group %s",
		p.opts.Dir, p.report.Group))
	return nil
}

// agentConfig writes each enrolled agent's configuration into the tree.  What
// the hook costs differs by agent -- Claude Code auto-approves Bash, Gemini CLI
// has no approval to give -- so the warning below reports the agent it just
// enrolled.
//
// An entry naming a path from an earlier layout is corrected rather than
// reported: a PreToolUse hook that cannot exec fails every command the agent
// runs.
func (p *project) agentConfig() error {
	if !p.opts.Hook {
		p.step("agent config", false, "--hook=false, so nothing this agent runs "+
			"here is redacted and its prompts are untouched")
		return nil
	}
	changed := false
	var written []string
	for _, target := range p.targets {
		for _, file := range target.files {
			path := filepath.Join(p.opts.Dir, file.path)
			if parent := filepath.Dir(path); parent != p.opts.Dir {
				if _, err := p.fs.ensureDir(parent, 0o700, p.uid, p.gid, false); err != nil {
					return err
				}
			}
			data, err := readAsset(file.asset)
			if err != nil {
				return err
			}
			// Merged, not overwritten: the file is the project's to edit, and
			// only the keys faramir writes are touched.
			write := p.fs.writeFile
			if file.merge {
				write = p.fs.mergeFile
			}
			made, err := write(path, data, file.mode, p.uid, p.gid)
			if err != nil {
				return err
			}
			changed = changed || made
			written = append(written, path)
		}
		if target.autoApprovesBash && changed {
			p.warn("Bash is now auto-approved in %s for %s: the hook rewrites every "+
				"command so its output can be redacted, and a rewritten command "+
				"matches no permission rule. Its deny list is what refuses one instead",
				p.opts.Dir, target.name)
		}
		if target.note != "" && changed {
			p.warn("%s: %s", target.name, target.note)
		}
	}
	// Named rather than counted, so an operator knows which file to merge.
	p.step("agent config", changed, strings.Join(written, ", "))

	// Reported, never acted on: a directory left behind by trying an agent is
	// not a decision to enrol it.
	var unenrolled []string
	for _, name := range detectedAgents(p.opts.Dir) {
		enrolled := false
		for _, target := range p.targets {
			if target.name == name {
				enrolled = true
			}
		}
		if !enrolled {
			unenrolled = append(unenrolled, name)
		}
	}
	if len(unenrolled) > 0 {
		p.warn("this tree also has configuration for %v, which was not enrolled: "+
			"nothing those agents run here is redacted. Pass --agent to include one",
			unenrolled)
	}
	return nil
}

// instructions writes the credentials section into the project's agent
// instructions file, between markers so a second run replaces it.
// Documentation, not enforcement: deleting the block changes nothing about what
// is reachable.
func (p *project) instructions() error {
	path := p.instructionsFile()
	snippet, err := readAsset("agent/claude/CLAUDE.md.snippet")
	if err != nil {
		return err
	}
	block := snippetBegin + "\n" + strings.TrimRight(string(snippet), "\n") + "\n" + snippetEnd + "\n"

	current, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	changed, err := p.fs.writeFile(path, spliceBlock(current, block), 0o644, p.uid, p.gid)
	if err != nil {
		return err
	}
	p.step("instructions", changed, path)
	return nil
}

// instructionsFile picks an existing file, or the first name.
func (p *project) instructionsFile() string {
	for _, name := range agentInstructionFiles {
		path := filepath.Join(p.opts.Dir, name)
		if exists(path) {
			return path
		}
	}
	return filepath.Join(p.opts.Dir, agentInstructionFiles[0])
}

// spliceBlock replaces the marked block in current, or appends it.
func spliceBlock(current []byte, block string) []byte {
	begin := bytes.Index(current, []byte(snippetBegin))
	end := bytes.Index(current, []byte(snippetEnd))
	if begin >= 0 && end > begin {
		var out bytes.Buffer
		out.Write(current[:begin])
		out.WriteString(block)
		out.Write(bytes.TrimLeft(current[end+len(snippetEnd):], "\n"))
		return out.Bytes()
	}
	if len(current) == 0 {
		return []byte(block)
	}
	return append(append(bytes.TrimRight(current, "\n"), "\n\n"...), block...)
}
