package config

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// sectionKeys is every section the loader accepts and the keys each takes.
// One structure, so the section list, the loaders and the docs test cannot
// drift apart. The daemon sections keep their names: [server], [keeper] and
// [executor] do describe faramir's own processes. The rest are named for what
// an operator is deciding.
var sectionKeys = map[string][]string{
	"server": {keySocketPath, "allowed_group", "agent_user"},
	"keeper": {keySocketPath, keyAllowedUser,
		"age_key_credential", "age_key_file"},
	"executor": {keySocketPath, keyAllowedUser},
	keyCommand: {"env", "timeout_sec", "max_timeout_sec", "concurrency",
		"max_memory_percent", "max_process_memory_mb"},
	"ssh": {keyKey, "agent_socket", "exec_group",
		"ssh_agent", "ssh_add"},
	"sudo": {"exec_user", "pam_service", "pam_stack", "helper",
		"notify_command", "timeout_sec"},
	"secret": {"min_length", "link", "block"},
	"audit":  {"log_path"},
}

func fromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

	// A section name that is nearly right -- [secrets] for [secret] -- would
	// leave a broker managing no files.
	if err := rejectUnknownSections(raw, slices.Sorted(maps.Keys(sectionKeys)), path); err != nil {
		return nil, err
	}

	if err := loadServer(raw, path, &cfg.Server); err != nil {
		return nil, err
	}
	if err := loadKeeper(raw, path, &cfg.Keeper); err != nil {
		return nil, err
	}
	if err := loadExecutor(raw, path, &cfg.Executor); err != nil {
		return nil, err
	}
	if err := loadCommand(raw, path, &cfg.Command); err != nil {
		return nil, err
	}
	if err := loadSecret(raw, path, &cfg.Secret); err != nil {
		return nil, err
	}
	if err := loadSsh(raw, path, &cfg.Ssh); err != nil {
		return nil, err
	}
	if err := loadSudo(raw, path, &cfg.Sudo); err != nil {
		return nil, err
	}
	if err := loadAudit(raw, path, &cfg.Audit); err != nil {
		return nil, err
	}
	// Last, both sections it reads being loaded by now.
	clampSudoTimeout(&cfg.Sudo, cfg.Command)
	return cfg, nil
}

// clampSudoTimeout holds a question to the longest a brokered command can be
// given. The command sits inside sudo for the whole question, so one that
// outlasts [command] max_timeout_sec is a question whose answer lands on a run
// the broker has already killed: the operator types yes, and the command it
// would have authorised is gone.
//
// Clamped rather than refused. The two keys are set for separate reasons and
// neither is wrong on its own, so a host that lowers max_timeout_sec would
// otherwise stop loading over a sudo timeout nobody thought to revisit -- and
// what that costs is every daemon on the host, for a value this can settle. The
// effective number is the one the config carries afterwards, so what `faramir
// doctor` reports and what a question is actually held to are the same.
func clampSudoTimeout(sudo *SudoConfig, command CommandConfig) {
	if sudo.TimeoutSec > command.MaxTimeoutSec {
		sudo.TimeoutSec = command.MaxTimeoutSec
	}
}

func loadServer(raw map[string]any, path string, out *ServerConfig) error {
	sec, where, err := section(raw, "server", path)
	if err != nil {
		return err
	}
	*out = ServerConfig{
		SocketPath:   "/run/faramir/broker.sock",
		AllowedGroup: "faramir-client",
	}
	return strFields(sec, where, []strField{
		{keySocketPath, &out.SocketPath},
		{"allowed_group", &out.AllowedGroup},
		{"agent_user", &out.AgentUser},
	})
}

func loadKeeper(raw map[string]any, path string, out *KeeperConfig) error {
	sec, where, err := section(raw, "keeper", path)
	if err != nil {
		return err
	}
	*out = KeeperConfig{
		SocketPath:  "/run/faramir/keeper.sock",
		AllowedUser: "faramir-broker", AgeKeyCredential: "age_key",
	}
	return strFields(sec, where, []strField{
		{keySocketPath, &out.SocketPath},
		{keyAllowedUser, &out.AllowedUser},
		{"age_key_credential", &out.AgeKeyCredential},
		{"age_key_file", &out.AgeKeyFile},
	})
}

func loadExecutor(raw map[string]any, path string, out *ExecutorConfig) error {
	sec, where, err := section(raw, "executor", path)
	if err != nil {
		return err
	}
	*out = ExecutorConfig{
		SocketPath:  "/run/faramir/exec.sock",
		AllowedUser: "faramir-broker",
	}
	return strFields(sec, where, []strField{
		{keySocketPath, &out.SocketPath},
		{keyAllowedUser, &out.AllowedUser},
	})
}

func loadCommand(raw map[string]any, path string, out *CommandConfig) error {
	sec, where, err := section(raw, "command", path)
	if err != nil {
		return err
	}
	*out = DefaultCommand()
	// 0 is not "no limit": it SIGTERMs the child the instant it starts.
	if out.TimeoutSec, err = atLeast(sec, "timeout_sec", where, out.TimeoutSec, 1); err != nil {
		return err
	}
	if out.MaxTimeoutSec, err = atLeast(sec, "max_timeout_sec", where, out.MaxTimeoutSec, 1); err != nil {
		return err
	}
	// 1, not 0: an unbuffered channel refuses every request as busy.
	if out.Concurrency, err = intInRange(sec, "concurrency", where, out.Concurrency, 1, MaxConcurrentRuns); err != nil {
		return err
	}
	// A floor of 1 rather than 0: this renders into MemoryMax, and a cgroup
	// allowed nothing kills every command as it starts. A percentage low enough
	// to be unusable is still the operator's to set -- a host running one small
	// command is a real case, and the executor's own cgroup is what the number
	// bounds. 100 is the whole machine, which is the same as no bound and is
	// spelled as one.
	if out.MaxMemoryPercent, err = intInRange(sec, "max_memory_percent", where,
		out.MaxMemoryPercent, 1, 100); err != nil {
		return err
	}
	// A floor of 256MB: below that ordinary commands fail to start, and a bound
	// that breaks `ansible-playbook` is turned off rather than lowered. The
	// ceiling is a sanity bound, a terabyte being past any host this runs on.
	if out.MaxProcessMemoryMB, err = intInRange(sec, "max_process_memory_mb", where,
		out.MaxProcessMemoryMB, 256, 1<<20); err != nil {
		return err
	}
	// Merged over the built-in table rather than replacing it, so a file that
	// sets TERM does not leave the broker resolving no bare program name.
	named, err := stringMap(sec["env"], where, nil)
	if err != nil {
		return err
	}
	maps.Copy(out.Env, named)

	// PATH decides which file a bare cmd[0] resolves to, and the broker resolves
	// it on behalf of a child that runs somewhere else, so a relative component
	// names two different directories. Blocked at load rather than skipped at
	// resolve time: the broker does not start, instead of running a file nobody
	// named.
	if out.Env["PATH"] == "" {
		return fmt.Errorf("%s: [command] env sets PATH to nothing, so no bare program "+
			"name resolves. Leave it out to keep the built-in %q", path, defaultPATH)
	}
	for component := range strings.SplitSeq(out.Env["PATH"], ":") {
		if filepath.IsAbs(component) {
			continue
		}
		shown := component
		if shown == "" {
			shown = "an empty component"
		}
		return fmt.Errorf("%s: [command] env PATH contains %s, which means the working directory. The broker "+
			"resolves a bare name from its own and the command runs in the request's, so the "+
			"file checked is not the file run. Name every directory absolutely", path, shown)
	}
	// Every request is clamped to max_timeout_sec, so a smaller one here would
	// replace timeout_sec rather than cap it.
	if out.MaxTimeoutSec < out.TimeoutSec {
		return fmt.Errorf("%s: [command] max_timeout_sec (%d) is below timeout_sec "+
			"(%d), which would silently override it for every command",
			path, out.MaxTimeoutSec, out.TimeoutSec)
	}
	return nil
}

func loadSecret(raw map[string]any, path string, out *SecretConfig) error {
	sec, where, err := section(raw, "secret", path)
	if err != nil {
		return err
	}
	*out = DefaultSecret()
	out.Patterns = secretPatterns(path)
	if out.Links, err = loadLinks(sec["link"], where); err != nil {
		return err
	}
	if out.Blocked, err = loadBlocked(sec["block"], where); err != nil {
		return err
	}
	// Six, not one: a shorter value is a matcher for something that occurs in
	// ordinary text. The floor is low rather than high because the failures are
	// not symmetric -- a value refused here is absent from the redactor and
	// reaches output in the clear, while one matched too eagerly only mangles the
	// operator's own text.
	if out.MinLength, err = atLeast(sec, "min_length", where, out.MinLength, 6); err != nil {
		return err
	}
	return nil
}

func loadSsh(raw map[string]any, path string, out *SshConfig) error {
	sec, where, err := section(raw, "ssh", path)
	if err != nil {
		return err
	}
	*out = SshConfig{
		AgentSocket: "/run/faramir/ssh-agent.sock",
		ExecGroup:   "faramir-exec", SshAgent: "/usr/bin/ssh-agent", SshAdd: "/usr/bin/ssh-add",
	}
	return strFields(sec, where, []strField{
		{keyKey, &out.Key},
		{"agent_socket", &out.AgentSocket},
		{"exec_group", &out.ExecGroup},
		{"ssh_agent", &out.SshAgent},
		{"ssh_add", &out.SshAdd},
	})
}

func loadSudo(raw map[string]any, path string, out *SudoConfig) error {
	sec, where, err := section(raw, "sudo", path)
	if err != nil {
		return err
	}
	// No exec_user by default, which is the install that granted no sudoers
	// entry: the rest describes where things would go if one ever did.
	*out = SudoConfig{
		PamService: "faramir-sudo",
		// No default: which file carries the stack depends on which sudo the host
		// has, and a guess here would be a config asserting something nobody
		// established. Absent means "look for either", which is what an install
		// made before this key existed leaves behind.
		PamStack: "",
		Helper:   "/usr/local/libexec/faramir/pam-escalate",
		// Nothing by default: `faramir sudo watch` is where a question is
		// seen and answered.
		NotifyCommand: nil,
		TimeoutSec:    DefaultSudoTimeoutSec,
	}
	if err := strFields(sec, where, []strField{
		{"exec_user", &out.ExecUser},
		{"pam_service", &out.PamService},
		{"pam_stack", &out.PamStack},
		{"helper", &out.Helper},
	}); err != nil {
		return err
	}
	if out.NotifyCommand, err = stringList(sec["notify_command"], where, out.NotifyCommand); err != nil {
		return err
	}
	// An announcement naming neither the command nor the question is one nobody
	// can act on. Empty is the default, and means the watcher is the only place
	// a question shows up.
	if len(out.NotifyCommand) > 0 && !slices.ContainsFunc(out.NotifyCommand, func(arg string) bool {
		return strings.Contains(arg, "{prompt}") || strings.Contains(arg, "{id}")
	}) {
		return fmt.Errorf("%s: notify_command names neither {prompt} nor {id}, so it "+
			"would announce that something is waiting without saying what", where)
	}
	// 0 would refuse every question the instant it was raised. See
	// MaxSudoTimeoutSec for the ceiling, and clampSudoTimeout for the other one:
	// what this section will accept, and what the [command] section leaves room
	// for, are separate questions and this is only the first.
	if out.TimeoutSec, err = intInRange(sec, "timeout_sec", where, out.TimeoutSec,
		1, MaxSudoTimeoutSec); err != nil {
		return fmt.Errorf("%w. A question is a human at a terminal and a host held "+
			"still while sudo waits on it, so this is bounded; past that, a refusal "+
			"and a second run is the better answer", err)
	}
	return nil
}

// MaxSudoTimeoutSec is the longest a question may wait for a human. The PAM
// helper's own deadline must outlast any question the broker will hold, or the
// helper would give up on a question still open and the operator's yes would
// land on a sudo that had already gone. The helper cannot read this config --
// it runs from PAM with no environment and a fixed argv -- so it derives its
// deadline from this constant and the two cannot drift.
//
// An hour: while a question is open sudo blocks and every other brokered
// command on the host is refused, so a long timeout is a long stall on the
// whole host. It is the operator who decides how long they are willing to hold
// it, and a converge started before someone walks to a terminal is a real case;
// what this bounds is a question outliving the session that raised it.
const MaxSudoTimeoutSec = 3600

func loadAudit(raw map[string]any, path string, out *AuditConfig) error {
	sec, where, err := section(raw, "audit", path)
	if err != nil {
		return err
	}
	*out = AuditConfig{LogPath: "/var/log/faramir/audit.log"}
	return strFields(sec, where, []strField{{"log_path", &out.LogPath}})
}
