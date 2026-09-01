package config

// ServerConfig describes the broker's own socket, the one an operator reaches.
// Callers are named by group rather than by uid, a uid list stopping being true
// the moment an account is renumbered. One group, `faramir init
// --client-group` naming one.
type ServerConfig struct {
	SocketPath   string
	AllowedGroup string
	// AgentUser is the account the coding agent runs as, which is the operator.
	// Named in a brokered command's environment as FARAMIR_OPERATOR, and in the
	// sudo one too: every brokered command runs as the executor, so nothing a
	// command can read of its own identity says whose host it is on.
	AgentUser string
}

// CommandConfig is what a brokered command is given and what bounds it. Named
// for the command rather than for the daemon that forks it, which is not what
// an operator is deciding when they set a timeout. No working directory here:
// a brokered command runs where its caller was.
type CommandConfig struct {
	// Env is the child's entire environment; the broker's own is never inherited.
	// Setting one name keeps the rest.
	Env map[string]string
	// TimeoutSec is what a request that names no timeout of its own gets.
	TimeoutSec int
	// MaxTimeoutSec is the ceiling every request is clamped to, and, less
	// obviously, the idle bound between chunks of a redact stream.
	MaxTimeoutSec int
	// Concurrency is how many brokered commands run at once; the rest are refused
	// busy. On a host with an escalation grant, raising it makes an escalation
	// harder to get: a sudo is refused while any other brokered command is in
	// flight.
	Concurrency int
	// MaxMemoryPercent is how much of the machine's memory every brokered
	// command together may hold, as the executor unit's MemoryMax. A percentage
	// rather than a size: it is the one form with a default that means the same
	// thing on a laptop and on a build host, and nothing here knows how much
	// memory the host has.
	//
	// The backstop rather than the bound. It is a cgroup total, so it cannot tell
	// one process holding everything from twenty holding a fair share each, and
	// it counts page cache besides. What it catches is fan-out, which no
	// per-process limit can see.
	//
	// Read by `faramir init`, which renders it into the unit. The daemons do not
	// enforce it; the kernel does, and it chooses a victim inside the executor's
	// own cgroup rather than across the whole machine.
	MaxMemoryPercent int
	// MaxProcessMemoryMB is what one brokered process may allocate, as the
	// executor unit's LimitDATA. Every child inherits it.
	//
	// The bound that matches the failure: a command that runs away is one process
	// asking for far more than any real one, while a parallel build is many
	// processes each asking for a little. A cgroup total cannot separate those
	// and this does. It counts anonymous memory only, so a command that reads or
	// writes a great deal is not charged for the page cache it leaves behind, and
	// a process that reaches it gets an allocation failure it can report rather
	// than the OOM killer.
	MaxProcessMemoryMB int
}

// KeeperConfig describes the process that holds the age key: separate uid,
// separate socket, no operation that returns the key. AllowedUser names the
// broker, one account rather than a list, a second being a second reader of the
// age key. No allowed_group, the only group in play holding the agent's own
// uid.
type KeeperConfig struct {
	SocketPath       string
	AllowedUser      string
	AgeKeyCredential string
	AgeKeyFile       string
}

// ExecutorConfig describes the process that forks brokered commands. Its uid
// holds no age key, values, audit log or SSH keys; a child forked by the broker
// would inherit all four. No concurrency of its own: the broker is the only
// client this socket admits and holds one [command] slot for the whole of each
// child, so that cap binds first; the executor keeps a fixed backstop.
type ExecutorConfig struct {
	SocketPath  string
	AllowedUser string
}

// SshConfig is an ssh-agent the broker owns, for a key the executor must not
// read. With no Key no agent is started, and SSH authenticates however the
// operator arranged it for the executor's uid.
type SshConfig struct {
	Key         string
	AgentSocket string
	ExecGroup   string
	SshAgent    string
	SshAdd      string
}

// SudoConfig is how a brokered command becomes root on this host: it does
// not authenticate, it asks. With no ExecUser nothing is granted and no
// question can be raised, which is the install that never passed --allow-sudo.
// Everything here but TimeoutSec is init's.
type SudoConfig struct {
	// ExecUser is the account the sudoers entry was written for, and the switch
	// for the whole arrangement. The helper checks PAM_USER against it, so a PAM
	// service reached for some other account authenticates nothing.
	ExecUser string
	// PamService is the sudoers `pam_service` name, which on a host whose sudo
	// takes that setting is the file under /etc/pam.d that sudo reads for this
	// account alone: a mistake in it reaches this account and leaves every other
	// sudo untouched.
	PamService string
	// PamStack is the file that actually carries that stack on this host, which
	// is not always the one PamService names. sudo-rs has no pam_service and
	// reaches the service called `sudo` for everybody, so there the stack is a
	// delimited block inside /etc/pam.d/sudo and no service file exists at all.
	//
	// Recorded rather than inferred, so reading config.toml says what this host
	// is. Empty in a config written before the key existed, and every reader
	// falls back to looking for either arrangement.
	PamStack string
	// Helper is what the PAM service execs. Named here so --check and doctor can
	// say whether it is there and who can write it.
	Helper string
	// NotifyCommand announces that a question is waiting, "{prompt}" being the
	// line the broker builds and "{id}" the question to answer. Optional and
	// answerless: whatever it runs cannot approve anything.
	NotifyCommand []string
	// TimeoutSec is how long a question waits for an answer before it is refused.
	// Held at load to [command] max_timeout_sec as well as to MaxSudoTimeoutSec:
	// the command waits inside sudo for the whole question, so a question that
	// outlasts the longest run cannot be answered in time. See clampSudoTimeout.
	TimeoutSec int
}

type SecretConfig struct {
	// Patterns and DecryptCommand are derived rather than configured, filled in
	// at load so that everything reading them reads one value. See
	// SecretPatterns and DecryptCommand.
	Patterns       []string
	DecryptCommand []string
	// MinLength is the floor a value has to clear to be held at all. Below it a
	// value matches inside ordinary words and the redactor eats the output; above
	// it a real credential is refused, absent from the redactor, and printed in
	// the clear. The second is the direction that leaks, which is why the floor
	// is low and the default is not.
	MinLength int
	// Links is the secrets read from files the operator's own tools maintain,
	// each named individually rather than matched by a glob. See Link.
	Links []Link
	// Blocked is the paths the agent's file tools are refused without faramir
	// reading them. Under [secret] because that is what these files hold, not
	// because the broker serves anything out of them. See BlockedPath.
	Blocked []BlockedPath
}

// AuditConfig is the operator-only record of what the broker ran. Output is
// recorded after redaction, so it holds no value.
type AuditConfig struct {
	LogPath string
}

type Config struct {
	// The file this config was loaded from. Reported by status and --check.
	Path     string
	Server   ServerConfig
	Keeper   KeeperConfig
	Executor ExecutorConfig
	Command  CommandConfig
	Ssh      SshConfig
	Sudo     SudoConfig
	Secret   SecretConfig
	Audit    AuditConfig
}
