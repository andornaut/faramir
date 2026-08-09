package install

// Enrolling one project, as against provisioning the host.
//
// The two are different jobs with different lifetimes.  `init` runs once per
// machine and again to upgrade it; this runs once per tree you want to work in,
// and there is no limit to how many of those there are.  Keeping them apart is
// also what makes the working directory safe to default here and unsafe there:
// this command means "enrol this project", so where you are standing is the
// answer, while init means "provision this host" and would enrol whatever
// directory it happened to be run from, including the faramir checkout.

import (
	"bytes"
	"fmt"
	"os"
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

// agentInstructionFiles are the names an agent reads, most specific first.  An
// existing one is used; when there is none, the first is created.
var agentInstructionFiles = []string{"AGENTS.md", "CLAUDE.md"}

// ProjectOptions is one enrolment.
type ProjectOptions struct {
	// Dir is the tree to enrol.  Defaults to the working directory.
	Dir string
	// Operator owns the tree.  It keeps owning it; what this grants is group
	// access for the executor's uid.
	Operator string
	// ConfigDir is where the installed config is read from, which is where the
	// shared group is learned.  A --group flag here could disagree with what
	// the sockets actually admit, and a tree shared with the wrong group is one
	// the executor cannot enter, with nothing to say so.
	ConfigDir string
	// Group overrides the group read from the config.  For a host whose config
	// is not readable, not for ordinary use.
	Group string
	// Hook registers the PreToolUse hook in the project's own agent settings.
	// That is what redacts the output of everything the agent runs there, and
	// it auto-approves Bash for the project as a side effect: a rewritten
	// command matches no permission rule, so the hook's deny list becomes the
	// only thing that refuses one.
	Hook bool
	// Agents names which coding agents to enrol.  Empty means Claude Code, so a
	// command written before this existed keeps doing what it did.
	//
	// Named rather than detected: enrolling costs something on some agents, and
	// a directory left behind by trying one once is not a decision to enrol it.
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
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return ProjectReport{}, err
	}
	opts.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}
	if opts.Operator == "" || opts.Operator == "root" {
		return ProjectReport{}, fmt.Errorf("name the account that works in %s: pass "+
			"--operator, set OPERATOR, or run through sudo so SUDO_USER carries it. "+
			"The tree belongs to somebody, and root here would chown a checkout away "+
			"from its owner", dir)
	}
	if os.Geteuid() != 0 && !opts.DryRun {
		return ProjectReport{}, fmt.Errorf("faramir init-project must run as root: it " +
			"changes group ownership and modes on directories you do not own")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ProjectReport{}, fmt.Errorf("no directory at %s", dir)
	}

	targets, err := resolveAgents(opts.Agents)
	if err != nil {
		return ProjectReport{}, err
	}
	run := &project{opts: opts, fs: fsys{dryRun: opts.DryRun}, targets: targets}
	run.report = ProjectReport{Version: version.Version, Dir: dir, DryRun: opts.DryRun}
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

type project struct {
	opts   ProjectOptions
	fs     fsys
	report ProjectReport
	uid    int
	gid    int
	// Resolved from opts.Agents before any step runs, so an unknown name stops
	// the run before the tree's ownership has been changed.
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
//
// allowed_groups is what the broker socket admits, so it is the only value that
// makes a shared tree usable.  Taking it from a flag instead is how a tree ends
// up group-owned by something the sockets do not admit: every mode is right,
// every check passes, and the executor still cannot enter.
func (p *project) resolveGroup() error {
	if p.opts.Group != "" {
		p.report.Group = p.opts.Group
		return nil
	}
	configFile := filepath.Join(p.opts.ConfigDir, "config.toml")
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("cannot read the shared group from %s: %w\n"+
			"Run faramir init first, pass --config-dir if the config is elsewhere, "+
			"or pass --group to name it directly", configFile, err)
	}
	if len(cfg.Server.AllowedGroups) == 0 {
		return fmt.Errorf("%s admits no group, so a shared tree would reach nothing. "+
			"Set allowed_groups", configFile)
	}
	// The first, when there are several: it is the one a tree can be given, and
	// a tree has one group.
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
	// writable tree, so a tree outside it gets the group and the setgid bits and
	// then refuses every write with EROFS.  Sharing it looks like it worked.
	if homeOf(p.opts.Dir) == "" {
		p.warn("%s is outside /home, which is the only tree faramir-exec may write. "+
			"A brokered command can enter it and still gets EROFS on every write. "+
			"Add a drop-in extending ReadWritePaths= on faramir-exec.service",
			p.opts.Dir)
	}
	// Reported as no change: it re-applies a group, setgid bits and a mode that
	// are already what they should be on every run after the first.
	p.step("share tree", false, fmt.Sprintf("%s with group %s",
		p.opts.Dir, p.report.Group))
	return nil
}

// agentConfig writes each enrolled agent's own configuration into the tree.
//
// The hook is what redacts the output of everything the agent runs there, and
// what it costs differs by agent: on Claude Code a rewritten command matches no
// permission rule and the hook must approve it, so Bash is auto-approved for
// the project; on Gemini CLI there is no approval to give, so the prompts stay
// as they were.  The warning below reports the agent it just enrolled rather
// than a rule that is only true of one of them.
//
// A tree enrolled by an install whose hook and MCP server were separate
// binaries is corrected rather than reported: the merge drops the entry naming
// the old path and writes the current one in its place.  A PreToolUse hook that
// cannot exec denies nothing, rewrites nothing, and fails every command the
// agent runs, so leaving one in place to be merged by hand is not an option.
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
			// Merged rather than overwritten: a settings file is the project's
			// to edit and holds hooks, servers and permissions faramir knows
			// nothing about.  Only the keys faramir writes are touched.
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
	// Named rather than counted: an operator reading this has to know which
	// file to merge when one was kept.
	p.step("agent config", changed, strings.Join(written, ", "))

	// Reported, never acted on.  A directory left behind by trying an agent once
	// is not a decision to enrol it, and enrolling is not free.
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
// instructions file.
//
// Between markers rather than appended, so a second run replaces what the first
// wrote.  This is documentation, not enforcement: the hook and the filesystem
// permissions are what bound the agent, and deleting this block must not change
// what is reachable.
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

// instructionsFile picks the file an agent will actually read: an existing one,
// or the first name when the project has none.
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
