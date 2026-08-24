// Package config loads /etc/faramir/config.toml. There is no command
// allowlist: the broker runs what it is asked to, as a uid that holds nothing,
// and redacts the output.
//
// Decoded into a raw map and hand-validated rather than unmarshalled into
// structs, so a mistyped key is named rather than ignored.
package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/termsafe"
)

const (
	DefaultConfigPath = "/etc/faramir/config.toml"
	defaultPATH       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// The one key three sections share, named once so the list of keys a section
	// accepts and the lookup that reads it cannot drift apart.
	keySocketPath = "socket_path"
	// keyPath is the TOML key both entry kinds spell a file with.
	keyPath = "path"
	// keyCommand is the TOML key a [[secret.block]] entry names a command with,
	// and the section name [command] happens to be the same word.
	keyCommand = "command"
)

// The limits no config key reaches. Variables rather than constants so a test
// can narrow one to exercise the limit without building a megabyte of output;
// nothing else assigns them.
var (
	// MaxOutputBytes bounds what a brokered command returns. Not a property of
	// the host: what it limits is how much text reaches the model. Truncation is
	// reported, so the cap is visible when it bites. 256 KiB is roughly 64k
	// tokens, which is under the context window it exists to protect.
	MaxOutputBytes = 256 << 10
	// MaxRequestBytes is the largest request the broker socket will read, a
	// guard against a malformed one rather than a size anybody chooses.
	MaxRequestBytes = 262144
	// MaxRecordBytes is the largest one audit record's line may be, counted in
	// the bytes it spends once encoded. internal/audit excerpts the output and
	// cuts every other field to fit, so a long command degrades the record rather
	// than failing to write one. Matched to MaxOutputBytes, which is what fills
	// it; encoding expands what a command wrote, so an output at the cap still
	// excerpts here.
	MaxRecordBytes = 256 << 10
	// TermCols and TermRows are the PTY every child is given. Cosmetic: they
	// decide where a program folds its own output.
	TermCols = 120
	TermRows = 40
	// KillGraceSec is the pause between SIGTERM and SIGKILL, a window that only
	// opens once a command has already overrun its timeout.
	KillGraceSec = 5
)

// MaxConcurrentRuns is the most brokered commands the executor will fork at
// once, and so the ceiling on [command] concurrency. Here rather than in
// internal/execserver so the loader can hold the setting to it: the executor is
// a backstop against a broker with a bug, and a concurrency above it made the
// executor the limiter instead, where the surplus met `exec_failed: busy` from
// the wrong layer after the run had already been registered and recorded as
// started.
const MaxConcurrentRuns = 16

// MinRecordBytes is the smallest record limit internal/audit is built to
// survive, not a value anybody sets. A record keeps its identity when
// everything else has been cut away -- the log_id, the op and the caller -- and
// the reducer is held to producing one at this size, which is what makes it
// safe at any larger one.
const MinRecordBytes = 4096

// DefaultCommand is what a brokered command gets when the file names nothing.
// The installer renders these values and the loader supplies them, so the file
// init writes and the file it would load cannot disagree about a default.
func DefaultCommand() CommandConfig {
	return CommandConfig{
		Env: map[string]string{
			"PATH": defaultPATH, "TERM": "xterm-256color", "LANG": "C.UTF-8",
			"LC_ALL": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive",
		},
		TimeoutSec: 600, MaxTimeoutSec: 3600, Concurrency: 10,
		MaxMemoryPercent: 25, MaxProcessMemoryMB: 4096,
	}
}

// DefaultSecret is DefaultCommand for the store.
func DefaultSecret() SecretConfig {
	return SecretConfig{DecryptCommand: DecryptCommand(), MinRefreshSec: 1, MinLength: 8}
}

// DefaultEscalationTimeoutSec is how long a question waits for a human.
const DefaultEscalationTimeoutSec = 120

// DecryptCommand is how the keeper invokes sops. Never a config key: the
// account this runs as is the one holding the age key.
func DecryptCommand() []string {
	return []string{"sops", "--output-type", "json", "--decrypt", "{file}"}
}

// SecretPatterns is the managed store, derived from where the config sits
// rather than configured, so it cannot be pointed at a checkout that a clone or
// a branch could move. One extension, not the three sops can read: faramir
// writes the store, and a second spelling would be a second way for a file to
// be named.
func SecretPatterns(configPath string) []string {
	dir := filepath.Join(filepath.Dir(configPath), "secrets")
	return []string{filepath.Join(dir, "*.sops.yml")}
}

// rejectUnknownKeys fails on a mistyped key, naming it and the alternatives.
func rejectUnknownKeys(raw map[string]any, known []string, where string) error {
	return rejectUnknown(raw, known, where, "key")
}

// rejectUnknownSections is the same check one level up, over [tables].
func rejectUnknownSections(raw map[string]any, known []string, where string) error {
	return rejectUnknown(raw, known, where, "section")
}

func rejectUnknown(raw map[string]any, known []string, where, noun string) error {
	var unknown []string
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	for k := range raw {
		if !set[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	sorted := append([]string(nil), known...)
	sort.Strings(sorted)
	return fmt.Errorf("%s: unknown %s(s): %s; known %ss: %s",
		where, noun, strings.Join(unknown, ", "), noun, strings.Join(sorted, ", "))
}

// table returns one [section] as a map, rejecting a scalar written in its
// place.
func table(raw map[string]any, key, where string) (map[string]any, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return map[string]any{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a [%s] table, got %T", where, key, value)
	}
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out, nil
}

func stringList(value any, where string, fallback []string) ([]string, error) {
	if value == nil {
		return fallback, nil
	}
	if s, ok := value.(string); ok {
		return nil, fmt.Errorf("%s: expected a list of strings, got string (write it as [%q])", where, s)
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a list of strings, got %T", where, value)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: expected a string, got %T: %v", where, v, v)
		}
		out = append(out, s)
	}
	return out, nil
}

func stringMap(value any, where string, fallback map[string]string) (map[string]string, error) {
	if value == nil {
		return fallback, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a table of strings, got %T", where, value)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: %s: expected a string, got %T", where, k, v)
		}
		out[k] = s
	}
	return out, nil
}

func str(value any, where string, fallback string) (string, error) {
	if value == nil {
		return fallback, nil
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s: expected a string, got %T", where, value)
	}
	return s, nil
}

func integer(value any, where string, fallback int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	n, ok := value.(int64)
	if !ok {
		return 0, fmt.Errorf("%s: expected an integer, got %T", where, value)
	}
	return int(n), nil
}

// intInRange is the value check the sizes and counts need: concurrency = -1
// panics on startup, 0 refuses every request as busy, and timeout_sec = 0 kills
// every command as it starts.
func intInRange(sec map[string]any, key, where string, fallback, low, high int) (int, error) {
	n, err := integer(sec[key], where, fallback)
	if err != nil {
		return 0, err
	}
	if n < low || n > high {
		if high == maxInt {
			return 0, fmt.Errorf("%s: %s must be at least %d, got %d", where, key, low, n)
		}
		return 0, fmt.Errorf("%s: %s must be between %d and %d, got %d", where, key, low, high, n)
	}
	return n, nil
}

// atLeast is intInRange with no upper bound worth naming.
func atLeast(sec map[string]any, key, where string, fallback, low int) (int, error) {
	return intInRange(sec, key, where, fallback, low, maxInt)
}

const maxInt = int(^uint(0) >> 1)

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

// EscalationConfig is how a brokered command becomes root on this host: it does
// not authenticate, it asks. With no ExecUser nothing is granted and no
// question can be raised, which is the install that never passed --allow-sudo.
// Everything here but TimeoutSec is init's.
type EscalationConfig struct {
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
	TimeoutSec int
}

type SecretConfig struct {
	// Patterns and DecryptCommand are derived rather than configured, filled in
	// at load so that everything reading them reads one value. See
	// SecretPatterns and DecryptCommand.
	Patterns       []string
	DecryptCommand []string
	// MinRefreshSec is the soonest the broker will ask the keeper again whether a
	// managed file changed. It does not bound the linked files: the broker stats
	// those on every request, so a credential another tool has just rotated is in
	// the redactor at once.
	//
	// It is how long a rotated managed value stays outside the redactor, which is
	// why the default is a second rather than something an idle host would notice
	// saving. The question is a stat per managed file and costs about 0.04 ms on a
	// command that already costs two milliseconds; raising it buys nothing worth
	// the window it opens, and the window opens exactly when an operator has just
	// rotated a value and runs a command to see that it took.
	MinRefreshSec int
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

// Link is one secret the broker reads from a file outside the managed store: an
// API token in a tool's own dotfile, kept where that tool expects it so that
// rotating it is that tool's business.
//
// The broker reads these, not the keeper: a linked file needs no age key, and
// the keeper runs with the homes taken away entirely, while the broker already
// holds every plaintext value and sees the homes to stat a request's cwd.
//
// One entry is one ref with one selector. Flattening a whole file would put
// its ordinary strings in the value set, and a registry URL is long enough to
// clear min_length and common enough to turn unrelated output into tokens.
type Link struct {
	// Ref is the name a caller asks by, in the same flat namespace the sops store
	// uses. Nothing marks a ref as linked, or moving one into the store later
	// would rename it.
	Ref string `json:"ref"`
	// Path is the file, absolute. No "~": a config file has no home to expand.
	Path string `json:"path"`
	// Type is how the file is read. See internal/secretlink.
	Type string `json:"type"`
	// Key selects one value out of a structured file, and is required for exactly
	// the types that select.
	Key string `json:"key,omitempty"`
}

// BlockedPath is a file the agent's own tools are refused and faramir does not
// read: a LUKS keyfile, an SSH identity, anything whose value it has no use
// for. Named in full or by a pattern, which are Path and Name: exactly one of
// them, an entry saying both being two rules written as one.
//
// The two forms are not interchangeable. A path refuses the file at that path
// on this host. A name refuses every file whose name matches, wherever it
// turns up, which is what reaches a path this host does not have: a container
// mounts /srv/ha/config as /config, and the agent names the second, so a rule
// carrying the first covers nothing it runs.
//
// The weaker half of the pair, and deliberately so. A [[secret.link]] entry
// regroups its file to the broker's group, so a brokered command is refused it
// too, and puts the value in the redactor, so the value is tokenised wherever
// it turns up. This does neither: it renders one deny rule into each agent's
// rule file and stops there. A command the broker runs may still open the file
// if its mode allows, and what it prints is in the clear, there being no value
// in the redactor to match.
//
// That is the trade it exists for. Reading the value would mean holding it,
// and these are the files whose value faramir should never hold.
type BlockedPath struct {
	// Path is the file or directory, absolute. No "~", for the reason a link's
	// path carries none: nothing expands one here.
	Path string `json:"path,omitempty"`
	// Name is a file name, a suffix, a prefix, a name with a wildcard in it, or
	// a directory tail ending in "/", matched against the path an agent names
	// rather than against this host's filesystem. The same forms the built-in
	// rules are written in, and rendered by the same code.
	Name string `json:"name,omitempty"`
	// Command is a command the agent's shell may not run, written the way it
	// would be typed: "op read", "sops -d". Not a path and not a pattern, so it
	// reaches the command guard alone and no agent's file-tool rules.
	//
	// The words, not a regular expression. Everything in it is taken literally
	// and the spaces between the words match any run of whitespace, so an
	// operator declares what they mean without a language in between and cannot
	// write one that matches more than it looks like.
	Command string `json:"command,omitempty"`
}

// Blocks is what an entry names, whichever form it took, for a message or a
// listing that wants one string.
func (r BlockedPath) Blocks() string {
	switch {
	case r.Name != "":
		return r.Name
	case r.Command != "":
		return r.Command
	}
	return r.Path
}

// AuditConfig is the operator-only record of what the broker ran. Output is
// recorded after redaction, so it holds no value.
type AuditConfig struct {
	LogPath string
}

type Config struct {
	// The file this config was loaded from. Reported by status and --check.
	Path       string
	Server     ServerConfig
	Keeper     KeeperConfig
	Executor   ExecutorConfig
	Command    CommandConfig
	Ssh        SshConfig
	Escalation EscalationConfig
	Secret     SecretConfig
	Audit      AuditConfig
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("FARAMIR_CONFIG")
	}
	if path == "" {
		path = DefaultConfigPath
	}
	raw, err := readTOML(path)
	if err != nil {
		return nil, err
	}
	cfg, err := fromMap(raw, path)
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	return cfg, nil
}

// Check holds a config to every rule Load applies, from bytes and without
// touching the filesystem. The installer renders this file and then replaces
// the one the daemons read, so a value they would refuse has to be caught
// before the write: afterwards the broker cannot start, and `faramir init`
// refuses to run against a config it cannot parse.
func Check(data []byte, path string) error {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	_, err := fromMap(raw, path)
	return err
}

// BaseLinks is the links this install declares, for a caller about to rewrite
// the file. A file that is not there yields nothing, which is a first
// install.
func BaseLinks(path string) ([]Link, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Secret.Links, nil
}

// BaseBlocked is the blocked paths this install declares, for a caller about to
// rewrite the file. A file that is not there yields nothing, which is a first
// install.
func BaseBlocked(path string) ([]BlockedPath, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Secret.Blocked, nil
}

// ValidateLink holds one entry to what the loader would accept, for a command
// that builds one before anything writes it.
func ValidateLink(link Link) error { return validateLink(link, "[[secret.link]]") }

func readTOML(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config not found: %s", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}

var (
	// The daemon sections keep their names: [server], [keeper] and [executor] do
	// describe faramir's own processes. The rest are named for what an operator
	// is deciding.
	sections = []string{"server", "keeper", "executor", keyCommand, "ssh",
		"escalation", "secret", "audit"}
	serverKeys = []string{keySocketPath, "allowed_group", "agent_user"}
	keeperKeys = []string{keySocketPath, "allowed_user",
		"age_key_credential", "age_key_file"}
	executorKeys = []string{keySocketPath, "allowed_user"}
	commandKeys  = []string{"env", "timeout_sec", "max_timeout_sec", "concurrency",
		"max_memory_percent", "max_process_memory_mb"}
	sshKeys = []string{"key", "agent_socket", "exec_group",
		"ssh_agent", "ssh_add"}
	escalationKeys = []string{"exec_user", "pam_service", "pam_stack", "helper",
		"notify_command", "timeout_sec"}
	secretKeys = []string{"min_length", "min_refresh_sec", "link", "block"}
	linkKeys   = []string{"ref", keyPath, "type", "key"}
	blockKeys  = []string{keyPath, "name", keyCommand}
	auditKeys  = []string{"log_path"}
)

func fromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

	// A section name that is nearly right -- [secrets] for [secret] -- would
	// leave a broker managing no files.
	if err := rejectUnknownSections(raw, sections, path); err != nil {
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
	if err := loadEscalation(raw, path, &cfg.Escalation); err != nil {
		return nil, err
	}
	if err := loadAudit(raw, path, &cfg.Audit); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadServer(raw map[string]any, path string, out *ServerConfig) error {
	where := path + ": [server]"
	sec, err := table(raw, "server", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, serverKeys, where); err != nil {
		return err
	}
	*out = ServerConfig{
		SocketPath:   "/run/faramir/broker.sock",
		AllowedGroup: "faramir-client",
	}
	if out.SocketPath, err = str(sec[keySocketPath], where, out.SocketPath); err != nil {
		return err
	}
	if out.AllowedGroup, err = str(sec["allowed_group"], where, out.AllowedGroup); err != nil {
		return err
	}
	if out.AgentUser, err = str(sec["agent_user"], where, out.AgentUser); err != nil {
		return err
	}
	return nil
}

func loadKeeper(raw map[string]any, path string, out *KeeperConfig) error {
	where := path + ": [keeper]"
	sec, err := table(raw, "keeper", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, keeperKeys, where); err != nil {
		return err
	}
	*out = KeeperConfig{
		SocketPath:  "/run/faramir/keeper.sock",
		AllowedUser: "faramir-broker", AgeKeyCredential: "age_key",
	}
	if out.SocketPath, err = str(sec[keySocketPath], where, out.SocketPath); err != nil {
		return err
	}
	if out.AllowedUser, err = str(sec["allowed_user"], where, out.AllowedUser); err != nil {
		return err
	}
	if out.AgeKeyCredential, err = str(sec["age_key_credential"], where, out.AgeKeyCredential); err != nil {
		return err
	}
	if out.AgeKeyFile, err = str(sec["age_key_file"], where, ""); err != nil {
		return err
	}
	return nil
}

func loadExecutor(raw map[string]any, path string, out *ExecutorConfig) error {
	where := path + ": [executor]"
	sec, err := table(raw, "executor", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, executorKeys, where); err != nil {
		return err
	}
	*out = ExecutorConfig{
		SocketPath:  "/run/faramir/exec.sock",
		AllowedUser: "faramir-broker",
	}
	if out.SocketPath, err = str(sec[keySocketPath], where, out.SocketPath); err != nil {
		return err
	}
	if out.AllowedUser, err = str(sec["allowed_user"], where, out.AllowedUser); err != nil {
		return err
	}
	return nil
}

func loadCommand(raw map[string]any, path string, out *CommandConfig) error {
	where := path + ": [command]"
	sec, err := table(raw, "command", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, commandKeys, where); err != nil {
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
	// A floor of 10: below that a converge is killed for doing its job, and a
	// bound nobody can live with is turned off rather than lowered. 100 is the
	// whole machine, which is the same as no bound and is spelled as one.
	if out.MaxMemoryPercent, err = intInRange(sec, "max_memory_percent", where,
		out.MaxMemoryPercent, 10, 100); err != nil {
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
	where := path + ": [secret]"
	sec, err := table(raw, "secret", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, secretKeys, where); err != nil {
		return err
	}
	*out = DefaultSecret()
	out.Patterns = SecretPatterns(path)
	if out.Links, err = loadLinks(sec["link"], where); err != nil {
		return err
	}
	if out.Blocked, err = loadBlocked(sec["block"], where); err != nil {
		return err
	}
	// At least 1: zero is what an unset flag looks like, so it cannot also mean
	// "ask on every request". A second is indistinguishable from none in
	// practice, and the linked files are not on this clock at all.
	if out.MinRefreshSec, err = atLeast(sec, "min_refresh_sec", where, out.MinRefreshSec, 1); err != nil {
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

// loadLinks validates every [[secret.link]] entry. Checked at load rather than
// where the file is read, so a typo stops the daemon rather than surfacing
// later as a value the redactor turns out not to have.
func loadLinks(value any, where string) ([]Link, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected [[secret.link]] tables, got %T "+
			"(write each entry as its own [[secret.link]] header)", where, value)
	}
	out := make([]Link, 0, len(entries))
	seen := map[string]bool{}
	for i, entry := range entries {
		at := fmt.Sprintf("%s: [[secret.link]] #%d", where, i+1)
		if err := rejectUnknownKeys(entry, linkKeys, at); err != nil {
			return nil, err
		}
		link := Link{}
		var err error
		if link.Ref, err = str(entry["ref"], at, ""); err != nil {
			return nil, err
		}
		if link.Path, err = str(entry["path"], at, ""); err != nil {
			return nil, err
		}
		if link.Type, err = str(entry["type"], at, ""); err != nil {
			return nil, err
		}
		if link.Key, err = str(entry["key"], at, ""); err != nil {
			return nil, err
		}
		if err := validateLink(link, at); err != nil {
			return nil, err
		}
		// A ref is the name a caller asks by, so two entries claiming one is
		// refused rather than resolved.
		if seen[link.Ref] {
			return nil, fmt.Errorf("%s: ref %q is claimed by more than one entry; "+
				"a ref has one definition", at, link.Ref)
		}
		seen[link.Ref] = true
		out = append(out, link)
	}
	return out, nil
}

// loadBlocked validates every [[secret.block]] entry. Held to the same rules a
// link's path is, minus everything about reading the file: there is no type, no
// key and no ref, because nothing is read out of it.
//
// A path that is not there is accepted. These are keys on volumes that are not
// always mounted, and a deny rule costs nothing while the file is absent, so
// refusing one would mean refusing the case the feature exists for.
func loadBlocked(value any, where string) ([]BlockedPath, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected [[secret.block]] tables, got %T "+
			"(write each entry as its own [[secret.block]] header)", where, value)
	}
	out := make([]BlockedPath, 0, len(entries))
	seen := map[string]bool{}
	for i, entry := range entries {
		at := fmt.Sprintf("%s: [[secret.block]] #%d", where, i+1)
		if err := rejectUnknownKeys(entry, blockKeys, at); err != nil {
			return nil, err
		}
		refused := BlockedPath{}
		var err error
		if refused.Path, err = str(entry["path"], at, ""); err != nil {
			return nil, err
		}
		if refused.Name, err = str(entry["name"], at, ""); err != nil {
			return nil, err
		}
		if refused.Command, err = str(entry[keyCommand], at, ""); err != nil {
			return nil, err
		}
		if err := validateBlocked(refused, at); err != nil {
			return nil, err
		}
		// Two entries naming one path or one pattern render one rule, so the
		// second is an operator who thinks something more was added. Keyed on the
		// form as well as the value: a path and a name that read alike are two
		// different rules.
		key := "path\x00" + refused.Path
		switch {
		case refused.Name != "":
			key = "name\x00" + refused.Name
		case refused.Command != "":
			key = "command\x00" + refused.Command
		}
		if seen[key] {
			return nil, fmt.Errorf("%s: %q is named by more than one entry",
				at, Shown(refused.Blocks()))
		}
		seen[key] = true
		out = append(out, refused)
	}
	return out, nil
}

// ValidateBlocked holds one entry to what the loader would accept, for a
// command that builds one before anything writes it.
func ValidateBlocked(refused BlockedPath) error {
	return validateBlocked(refused, "[[secret.block]]")
}

// validateBlocked sends an entry to the rules for the form it took, and refuses
// one that took both or neither. Neither is an empty entry rendering nothing;
// both is one entry asking for two rules, and answering it by picking a form
// would render the one the operator was not looking at.
func validateBlocked(blocked BlockedPath, at string) error {
	var named []string
	for _, form := range []struct{ key, value string }{
		{"path", blocked.Path}, {"name", blocked.Name}, {"command", blocked.Command},
	} {
		if form.value != "" {
			named = append(named, fmt.Sprintf("%s %q", form.key, form.value))
		}
		if err := refuseControl(form.key, form.value, at); err != nil {
			return err
		}
	}
	switch {
	case len(named) > 1:
		return fmt.Errorf("%s: names %s, and an entry is one of them: a path blocks that file here, a name "+
			"blocks every file it matches wherever it is, and a command blocks a command. "+
			"Write an entry each", at, strings.Join(named, " and "))
	case blocked.Name != "":
		return validateBlockedName(blocked.Name, at)
	case blocked.Command != "":
		return validateBlockedCommand(blocked.Command, at)
	}
	return validateBlockedPath(blocked, at)
}

// refuseControl refuses an entry carrying a control character, whichever form
// it took. Every one of these is rendered into a deny rule, and the rendered
// file is one rule per line, so a newline in an entry ends the rule early and
// starts a second line with the rest of it. Neither half is the rule that was
// asked for, both halves are unbalanced regular expressions that will not
// compile, and a pattern that does not compile is skipped: the entry an
// operator added to refuse one more file takes the rules protecting the install
// with it, and nothing on the host reports the loss.
//
// The other controls do not split a rule and are refused for a second reason: a
// listing prints these back to a terminal, and a carriage return or an escape
// sequence in an entry makes the row read as something other than what is
// stored. Refused where they are written rather than escaped where they are
// shown, an entry being text an operator chose.
func refuseControl(form, value, at string) error {
	// Decoded byte by byte rather than ranged over: ranging yields U+FFFD for a
	// byte that is not valid UTF-8, which is not Actionable, so the check would
	// not see it. Such a byte renders a rule Go's regexp refuses to compile, and
	// the hook skips a rule it cannot compile, which is the same loss by a
	// quieter route.
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("%s: %s %q carries a byte at offset %d that is not valid UTF-8, so the rule it "+
				"renders does not compile and refuses nothing", at, form, Shown(value), i)
		}
		if termsafe.Actionable(r) {
			return fmt.Errorf("%s: %s %q carries %q at offset %d. %s",
				at, form, Shown(value), r, i, whyControlIsRefused(r))
		}
		i += size
	}
	return nil
}

// whyControlIsRefused is which of the two reasons this character is refused
// for. The two are told apart because an operator reading that a tab splits a
// line goes looking for a line it did not split.
func whyControlIsRefused(r rune) string {
	if r == '\n' || r == '\r' {
		return "A rule is one line of a generated file, and this ends a line: " +
			"it splits the rule and leaves neither half working"
	}
	return "A listing prints an entry back to a terminal, and this makes the " +
		"row read as something other than what is stored"
}

// Shown is an entry as a message quotes it back. Bounded because the entry is
// whatever was pasted at the flag, and a message that repeats it is as long as
// the paste: a mistyped argument otherwise answers with a hundred kilobytes,
// with the sentence that says what to do at the far end of it.
//
// Exported for the warnings an add prints alongside these refusals, which
// quote the same entries and are bounded by the same number.
func Shown(entry string) string { return termsafe.Truncate(entry, maxShownBytes) }

// maxShownBytes is enough of an entry to recognise which one was refused. Past
// PATH_MAX, so no path this could name is cut.
const maxShownBytes = 8192

// validateBlockedCommand holds a command entry to what can be rendered. The
// words are taken literally, so there is no pattern to get wrong; what is left
// to check is that each word is long enough to mean one.
//
// An empty command is not checked here: validateBlocked reaches this only for a
// non-empty one, and an entry naming nothing at all is refused there as naming
// no form.
//
// A single letter would match every command carrying it as a word, which is
// most of them, and is the same failure "/" is as a path.
func validateBlockedCommand(command, at string) error {
	if strings.TrimSpace(command) != command {
		return fmt.Errorf("%s: command %q is padded with whitespace", at, Shown(command))
	}
	for word := range strings.FieldsSeq(command) {
		if len(word) < 2 {
			return fmt.Errorf("%s: command %q carries the single-character word %q, "+
				"which matches nearly every command line. Write the command as it "+
				"would be typed", at, Shown(command), Shown(word))
		}
	}
	return nil
}

func validateBlockedPath(refused BlockedPath, at string) error {
	if refused.Path == "" {
		return fmt.Errorf("%s: path, name or command is required; one of them is "+
			"the whole of the entry", at)
	}
	if strings.HasPrefix(refused.Path, "~") {
		return fmt.Errorf("%s: path %q starts with ~, which nothing expands here. "+
			"Write the path in full", at, Shown(refused.Path))
	}
	if !filepath.IsAbs(refused.Path) {
		return fmt.Errorf("%s: path %q is relative, and a deny rule is matched "+
			"against a path the agent names in full. Write it in full", at, Shown(refused.Path))
	}
	// A rule is a literal string in someone else's config, so the path that
	// reaches it has to be the one an agent would name. "/etc/./k" and "/etc/k"
	// are one file and would be two rules, one of which matches nothing.
	if clean := filepath.Clean(refused.Path); clean != refused.Path {
		return fmt.Errorf("%s: path %q is not in its shortest form, and a deny rule "+
			"matches the path as written. Use %q", at, Shown(refused.Path), Shown(clean))
	}
	// "/" would render a rule refusing the whole filesystem, which fails closed
	// and leaves the agent unable to read anything at all.
	if refused.Path == "/" {
		return fmt.Errorf("%s: path is /, which would refuse the agent every file "+
			"on the host. Name the file or the directory that holds it", at)
	}
	return nil
}

// validateBlockedName holds a name pattern to what can be rendered and what is
// worth rendering. The forms are the built-in rules' own: a file name, a suffix
// ("*.pem"), a prefix (".env*"), a name with a wildcard inside it
// ("secrets*.yml"), or a directory tail (".storage/").
//
// The failure this guards is the opposite of a path's. A mistyped path refuses
// one file and the operator meets the file still readable; a pattern that
// matches too much refuses a class of files at once, and the agent meets that
// as tools failing on files nobody discussed. So what is refused here is the
// pattern that matches everything, and `block add` prints what a pattern will
// match rather than leaving a wide one silent.
func validateBlockedName(name, at string) error {
	switch {
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("%s: name %q is padded with whitespace, and a rule matches "+
			"the pattern as written", at, Shown(name))
	case strings.HasPrefix(name, "~"):
		return fmt.Errorf("%s: name %q starts with ~, which nothing expands here", at, Shown(name))
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("%s: name %q is an absolute path, and a name is matched "+
			"against the end of what an agent names rather than the whole of it. "+
			"Write it as a path entry, or drop the leading /", at, Shown(name))
	case strings.Contains(name, "**"):
		return fmt.Errorf("%s: name %q carries **, and a name already matches in "+
			"any directory. Write the name itself", at, Shown(name))
	case slices.Contains(strings.Split(name, "/"), ".."):
		return fmt.Errorf("%s: name %q carries a .. segment, and a rule matches the "+
			"pattern as written rather than a path it resolves", at, Shown(name))
	}
	// What is left once the wildcards and the separators are taken out. Nothing
	// left is a pattern matching every file the agent can name, which fails
	// closed and leaves it unable to read anything at all: the same answer "/"
	// gets as a path.
	if strings.Trim(name, "*/") == "" {
		return fmt.Errorf("%s: name %q matches every file on the host, which would "+
			"refuse the agent all of them. Name the file, the suffix or the "+
			"directory that holds it", at, Shown(name))
	}
	return nil
}

func validateLink(link Link, at string) error {
	// The same pattern a faramir:// URI is parsed against: a ref outside it would
	// load and then be unreachable.
	if link.Ref == "" {
		return fmt.Errorf("%s: ref is required; it is the name a caller asks by", at)
	}
	if !secretref.Valid(link.Ref) {
		return fmt.Errorf("%s: ref %q is not a name a faramir:// reference can carry; "+
			"letters, digits, and then any of . _ - /", at, Shown(link.Ref))
	}
	if link.Path == "" {
		return fmt.Errorf("%s: path is required", at)
	}
	// The path is rendered into the agents' deny rules and into the guard's, so
	// it carries the same hazard a blocked entry does: one rule per line, and a
	// newline in the subject splits the rule into two fragments that will not
	// compile and are skipped. The key never reaches a rule, and is held to the
	// same bytes because both are printed back by `faramir link ls`.
	if err := refuseControl("path", link.Path, at); err != nil {
		return err
	}
	if err := refuseControl("key", link.Key, at); err != nil {
		return err
	}
	// A leading ~ is named separately from "not absolute": the daemons run as
	// their own accounts, so a home there would be the wrong one even if
	// something expanded it.
	if strings.HasPrefix(link.Path, "~") {
		return fmt.Errorf("%s: path %q starts with ~, which nothing expands here: the "+
			"broker runs as its own account, so a home would be the wrong one. Write "+
			"the path in full", at, link.Path)
	}
	if !filepath.IsAbs(link.Path) {
		return fmt.Errorf("%s: path %q is relative, and the broker's working "+
			"directory is not the operator's. Write it in full", at, link.Path)
	}
	if link.Type == "" {
		return fmt.Errorf("%s: type is required; one of %s", at,
			strings.Join(secretlink.Kinds(), ", "))
	}
	if !slices.Contains(secretlink.Kinds(), link.Type) {
		return fmt.Errorf("%s: unknown type %q; one of %s", at, link.Type,
			strings.Join(secretlink.Kinds(), ", "))
	}
	// Required and refused, rather than ignored where it means nothing: a key on
	// a whole-file link is an operator who believes something is being
	// selected.
	if secretlink.NeedsKey(link.Type) && link.Key == "" {
		return fmt.Errorf("%s: type %q selects one value out of the file, so key is "+
			"required", at, link.Type)
	}
	if !secretlink.NeedsKey(link.Type) && link.Key != "" {
		return fmt.Errorf("%s: type %q is the whole file, so key selects nothing; "+
			"remove it, or name a type that selects: %s", at, link.Type,
			strings.Join(selectingKinds(), ", "))
	}
	return nil
}

// selectingKinds is the types that take a key, for the message above.
func selectingKinds() []string {
	var out []string
	for _, kind := range secretlink.Kinds() {
		if secretlink.NeedsKey(kind) {
			out = append(out, kind)
		}
	}
	return out
}

func loadSsh(raw map[string]any, path string, out *SshConfig) error {
	where := path + ": [ssh]"
	sec, err := table(raw, "ssh", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, sshKeys, where); err != nil {
		return err
	}
	*out = SshConfig{
		AgentSocket: "/run/faramir/ssh-agent.sock",
		ExecGroup:   "faramir-exec", SshAgent: "/usr/bin/ssh-agent", SshAdd: "/usr/bin/ssh-add",
	}
	if out.Key, err = str(sec["key"], where, ""); err != nil {
		return err
	}
	if out.AgentSocket, err = str(sec["agent_socket"], where, out.AgentSocket); err != nil {
		return err
	}
	if out.ExecGroup, err = str(sec["exec_group"], where, out.ExecGroup); err != nil {
		return err
	}
	if out.SshAgent, err = str(sec["ssh_agent"], where, out.SshAgent); err != nil {
		return err
	}
	if out.SshAdd, err = str(sec["ssh_add"], where, out.SshAdd); err != nil {
		return err
	}
	return nil
}

func loadEscalation(raw map[string]any, path string, out *EscalationConfig) error {
	where := path + ": [escalation]"
	sec, err := table(raw, "escalation", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, escalationKeys, where); err != nil {
		return err
	}
	// No exec_user by default, which is the install that granted no sudoers
	// entry: the rest describes where things would go if one ever did.
	*out = EscalationConfig{
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
		TimeoutSec:    DefaultEscalationTimeoutSec,
	}
	if out.ExecUser, err = str(sec["exec_user"], where, ""); err != nil {
		return err
	}
	if out.PamService, err = str(sec["pam_service"], where, out.PamService); err != nil {
		return err
	}
	if out.PamStack, err = str(sec["pam_stack"], where, out.PamStack); err != nil {
		return err
	}
	if out.Helper, err = str(sec["helper"], where, out.Helper); err != nil {
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
	// MaxSudoTimeoutSec for the ceiling.
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
// Ten minutes: while a question is open sudo blocks and every other brokered
// command on the host is refused.
const MaxSudoTimeoutSec = 600

func loadAudit(raw map[string]any, path string, out *AuditConfig) error {
	where := path + ": [audit]"
	sec, err := table(raw, "audit", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, auditKeys, where); err != nil {
		return err
	}
	*out = AuditConfig{LogPath: "/var/log/faramir/audit.log"}
	if out.LogPath, err = str(sec["log_path"], where, out.LogPath); err != nil {
		return err
	}
	return nil
}
