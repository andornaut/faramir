// Package config loads /etc/faramir/config.toml.  There is no command
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

	"github.com/BurntSushi/toml"

	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretref"
)

const (
	DefaultConfigPath = "/etc/faramir/config.toml"
	defaultPATH       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// The values that are no longer keys.  Each stopped being one for a reason of
// its own; what they share is that no install ever set them, and that naming
// them here says "this is the shape of the thing" where a default in a struct
// says "here is a value you may want to change".
//
// Variables rather than constants for the same reason the install paths are:
// a test narrows one to exercise the limit without building a megabyte of
// output.  Nothing else assigns them, and no config key reaches them.
var (
	// MaxOutputBytes bounds what a brokered command returns.  Not a property of
	// the host: what it limits is how much text reaches the model, which belongs
	// to the conversation on the other end, and the only use for a larger one is
	// putting more in front of it.  Truncation is reported, so the cap is
	// visible when it bites rather than silently eating the tail.
	//
	// 256 KiB is roughly 64k tokens.  A megabyte was the earlier value and could
	// not do this job: it is more than the context window it exists to protect,
	// so one command could still bury the conversation it was run to inform.  A
	// cap that cannot bind is not a cap.
	MaxOutputBytes = 256 << 10
	// MaxRequestBytes is the largest request the broker socket will read, a
	// guard against a malformed one rather than a size anybody chooses.
	MaxRequestBytes = 262144
	// MaxRecordBytes is the largest one audit record's line may be, counted in
	// the bytes it spends once encoded.  internal/audit excerpts the output and
	// cuts every other field to fit, so a long command degrades the record
	// rather than failing to write one.
	//
	// Matched to MaxOutputBytes, which is what fills it.  Encoding expands what
	// a command wrote -- "<", ">", "&" and every control character cost six
	// apiece as JSON -- so an output at the cap still excerpts here, which is
	// the behaviour the reducer is built for and reports.
	MaxRecordBytes = 256 << 10
	// TermCols and TermRows are the PTY every child is given.  Cosmetic: they
	// decide where a program folds its own output, on a stream that is read by a
	// model rather than by a person.
	TermCols = 120
	TermRows = 40
	// KillGraceSec is the pause between SIGTERM and SIGKILL, a window that only
	// opens once a command has already overrun its timeout.
	KillGraceSec = 5
)

// MinRecordBytes is the smallest record limit internal/audit is built to
// survive, not a value anybody sets: MaxRecordBytes is fixed well above it.
// A record has an identity even when everything else has been cut away -- the
// log_id, the op and the caller -- and the reducer is held to producing one at
// this size, which is what makes it safe at any larger one.
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
	}
}

// DefaultSecret is DefaultCommand for the store.
func DefaultSecret() SecretConfig {
	return SecretConfig{DecryptCommand: DecryptCommand(), MinRefreshSec: 10, MinLength: 8}
}

// DefaultApprovalTimeoutSec is how long a question waits for a human.
const DefaultApprovalTimeoutSec = 120

// DecryptCommand is how the keeper invokes sops.  Never a key: a second way to
// invoke it is a second thing that could be pointed somewhere else, and the
// account this runs as is the one holding the age key.
func DecryptCommand() []string {
	return []string{"sops", "--output-type", "json", "--decrypt", "{file}"}
}

// SecretPatterns is the managed store, derived from where the config sits
// rather than configured.  Two things follow from deriving it: the store cannot
// be pointed at a checkout, which a clone or a branch could move, and the three
// extensions here are the three the agent deny rules already refuse, so what
// the broker reads and what the agent cannot open cannot disagree.
func SecretPatterns(configPath string) []string {
	dir := filepath.Join(filepath.Dir(configPath), "secrets")
	return []string{
		filepath.Join(dir, "*.sops.yml"),
		filepath.Join(dir, "*.sops.yaml"),
		filepath.Join(dir, "*.sops.json"),
	}
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
//
// Callers are named by group rather than by uid.  A uid list was a second
// spelling of the same answer that stopped being true the moment an account was
// renumbered, and nothing asked it a question allowed_group could not.
//
// One group, because `faramir init --client-group` names one and a drop-in may
// not set it.  A list held exactly one value on every install that existed.
type ServerConfig struct {
	SocketPath   string
	AllowedGroup string
}

// CommandConfig is what a brokered command is given and what bounds it.  Named
// for the command rather than for the daemon that forks it: a section called
// [command] described which of faramir's processes did the work, which is not what
// an operator is deciding when they set a timeout.
//
// No working directory here: a brokered command runs where its caller was.
type CommandConfig struct {
	// Env is the child's entire environment; the broker's own is never
	// inherited.  Setting one name keeps the rest, unlike a table that replaced
	// the whole of it and so had to name PATH itself or resolve nothing.
	Env map[string]string
	// TimeoutSec is what a request that names no timeout of its own gets.
	TimeoutSec int
	// MaxTimeoutSec is the ceiling every request is clamped to, and, less
	// obviously, the idle bound between chunks of a redact stream.
	MaxTimeoutSec int
	// Concurrency is how many brokered commands run at once; the rest are
	// refused busy.  On a host with an approval grant, raising it makes an
	// approval harder to get: a sudo is refused outright while any other
	// brokered command is in flight.
	Concurrency int
}

// KeeperConfig describes the process that holds the age key: separate uid,
// separate socket, no operation that returns the key.  The broker is the only
// client, which AllowedUser says: one account, not a list, because a second
// would be a second reader of the age key.  No allowed_group, because the only
// group in play holds the agent's own uid.
type KeeperConfig struct {
	SocketPath       string
	AllowedUser      string
	AgeKeyCredential string
	AgeKeyFile       string
}

// ExecutorConfig describes the process that forks brokered commands.  Its uid
// holds no age key, values, audit log or SSH keys; a child forked by the broker
// would inherit all four.
//
// No concurrency of its own.  The broker is the only client this socket admits and it
// holds one [command] concurrency slot for the whole of each child, so that
// cap binds first and always; the executor keeps a fixed backstop of its own.
type ExecutorConfig struct {
	SocketPath  string
	AllowedUser string
}

// SshConfig is an ssh-agent the broker owns, for a key the executor must not
// read.  With no Key no agent is started, and SSH authenticates however the
// operator arranged it for the executor's uid.
type SshConfig struct {
	Key         string
	AgentSocket string
	ExecGroup   string
	SshAgent    string
	SshAdd      string
}

// ApprovalConfig is how a brokered command becomes root on this host: it does
// not authenticate, it asks.  Named for the question rather than for sudo,
// which is only the thing that waits on the answer.  With no ExecUser nothing is granted and no question
// can be raised, which is the install that never passed --allow-sudo.
// Everything here but TimeoutSec is init's, each value naming a file or a
// program that decides whether an approval happens.
type ApprovalConfig struct {
	// ExecUser is the account the sudoers entry was written for, and the switch
	// for the whole arrangement.  The helper checks PAM_USER against it, so a PAM
	// service reached for some other account authenticates nothing.
	ExecUser string
	// PamService is the sudoers `pam_service` name, and so the file under
	// /etc/pam.d that sudo reads for that account alone.  Private on purpose: a
	// mistake in it reaches this account and leaves every other sudo untouched.
	PamService string
	// Helper is what the PAM service execs.  Named here so --check and doctor can
	// say whether it is there and who can write it.
	Helper string
	// NotifyCommand announces that a question is waiting, "{prompt}" being the
	// line the broker builds and "{id}" the question to answer.  Optional,
	// best-effort and answerless: whatever it runs cannot approve anything, the
	// answer coming back over the broker socket from a caller SO_PEERCRED says is
	// root.
	NotifyCommand []string
	// TimeoutSec is how long a question waits for an answer before it is refused.
	TimeoutSec int
}

type SecretConfig struct {
	// Patterns and DecryptCommand are derived rather than configured: no key
	// names either, and they are filled in at load so that everything reading
	// them reads one value.  See SecretPatterns and DecryptCommand for why
	// neither is settable.
	Patterns       []string
	DecryptCommand []string
	// MinRefreshSec is how often the broker asks the keeper whether a managed file
	// changed.  It does not bound the linked files: those are the operator's own
	// and this uid can stat them, so they are checked on every request and a
	// credential another tool has just rotated is in the redactor at once.
	MinRefreshSec int
	// MinLength is the floor a value has to clear to be held at all.  Below it a
	// value matches inside ordinary words and the redactor eats the output; above
	// it a real credential is refused, absent from the redactor, and printed in
	// the clear if it reaches output by any route.  The second is the direction
	// that leaks, which is why the floor is low and the default is not.
	MinLength int
	// Links is the secrets read from files the operator's own tools maintain,
	// each named individually rather than matched by a glob.  See Link.
	Links []Link
}

// Link is one secret the broker reads from a file outside the managed store: an
// API token in a tool's own dotfile, kept where that tool expects it so that
// rotating it is that tool's business and nothing here goes stale.
//
// The broker reads these, not the keeper.  The keeper exists to hold the age
// key, and it runs with the homes taken away entirely; a linked file needs no
// key, so widening the account that holds the one thing that decrypts everything
// would buy nothing.  The broker already holds every plaintext value and already
// sees the homes, having to stat a request's cwd.
//
// One entry is one ref with one selector.  Flattening a whole file would put its
// ordinary strings in the value set, and a config file is mostly not secret: a
// registry URL is long enough to clear min_length and common enough to turn
// unrelated output into tokens.
type Link struct {
	// Ref is the name a caller asks by, in the same flat namespace the sops store
	// uses.  Nothing marks a ref as linked: where a secret is kept is not part of
	// its name, or moving one into the store later would rename it.
	Ref string `json:"ref"`
	// Path is the file, absolute.  No "~": a config file has no home to expand.
	Path string `json:"path"`
	// Type is how the file is read.  See internal/secretlink.
	Type string `json:"type"`
	// Key selects one value out of a structured file, and is required for exactly
	// the types that select.
	Key string `json:"key,omitempty"`
}

// AuditConfig is the operator-only record of what the broker ran.  Output is
// recorded after redaction, so it holds no value.
type AuditConfig struct {
	LogPath string
}

type Config struct {
	Path string
	// Every file that contributed, which is one.  Reported by status and --check.
	Sources  []string
	Server   ServerConfig
	Keeper   KeeperConfig
	Executor ExecutorConfig
	Command  CommandConfig
	Ssh      SshConfig
	Approval ApprovalConfig
	Secret   SecretConfig
	Audit    AuditConfig
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
	// One file, so one source.  Kept as a list because it is what `status` and
	// `--check` report, and a reader asking "which files were read" wants the
	// answer rather than the shape it used to come in.
	cfg.Sources = []string{path}
	return cfg, nil
}

// Check holds a config to every rule Load applies, from bytes and without
// touching the filesystem.
//
// The installer renders this file and then replaces the one the daemons read,
// so a value they would refuse has to be caught before the write.  Afterwards
// is too late twice over: the broker cannot start, and `faramir init` refuses
// to run against a config it cannot parse, so the command that would repair it
// is the command that is blocked.
func Check(data []byte, path string) error {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	_, err := fromMap(raw, path)
	return err
}

// BaseLinks is the links this install declares.  There is one config file, so
// this is Load's answer without the rest of it: a caller about to rewrite the
// file needs the entries it already holds and nothing else.
//
// A file that is not there yields nothing, which is a first install.
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

// linkList is the other inventory, and the only array of tables in the file.
// Handled apart from inventoryLists because TOML decodes an array of tables as
// []map[string]any rather than []any, so it reaches neither list branch, and
// because its entries are deduplicated by ref rather than by equality.

// noFlagResolved marks a key init works out at install time rather than taking
// from a flag.  A sentinel rather than prose, so the remedy is matched exactly:
// a near-miss would fall through to the build-time wording, which is the one
// answer that sends an operator away from what would have changed the value.

var (
	// The daemon sections keep their names: [server], [keeper] and [executor] do
	// describe faramir's own processes, and nothing in them is a preference.
	// The rest are named for what an operator is deciding.
	sections = []string{"server", "keeper", "executor", "command", "ssh",
		"approval", "secret", "audit"}
	serverKeys = []string{"socket_path", "allowed_group"}
	keeperKeys = []string{"socket_path", "allowed_user",
		"age_key_credential", "age_key_file"}
	executorKeys = []string{"socket_path", "allowed_user"}
	commandKeys  = []string{"env", "timeout_sec", "max_timeout_sec", "concurrency"}
	sshKeys      = []string{"key", "agent_socket", "exec_group",
		"ssh_agent", "ssh_add"}
	approvalKeys = []string{"exec_user", "pam_service", "helper",
		"notify_command", "timeout_sec"}
	secretKeys = []string{"min_length", "min_refresh_sec", "link"}
	linkKeys   = []string{"ref", "path", "type", "key"}
	auditKeys  = []string{"log_path"}
)

func fromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

	// [secret] for [secret] leaves a broker managing no files.
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
	if err := loadApproval(raw, path, &cfg.Approval); err != nil {
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
		AllowedGroup: "dev",
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	if out.AllowedGroup, err = str(sec["allowed_group"], where, out.AllowedGroup); err != nil {
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
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
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
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
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
	if out.Concurrency, err = atLeast(sec, "concurrency", where, out.Concurrency, 1); err != nil {
		return err
	}
	// Merged over the built-in table rather than replacing it, so naming one
	// variable keeps the other four.  What that avoids is a file that sets TERM
	// and silently leaves the broker resolving no bare program name at all.
	named, err := stringMap(sec["env"], where, nil)
	if err != nil {
		return err
	}
	maps.Copy(out.Env, named)

	// PATH decides which file a bare cmd[0] resolves to, and it is resolved by the
	// broker on behalf of a child that runs somewhere else.  A component a shell
	// would read as its working directory is therefore two different directories
	// here, so it is refused at load rather than skipped at resolve time: the
	// broker does not start, instead of running a file nobody named.
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
		return fmt.Errorf("%s: [command] env PATH contains %s, which means the "+
			"working directory. The broker resolves a bare program name from its own "+
			"directory and the command runs in the request's, so the file checked "+
			"would not be the file run. Name every directory absolutely", path, shown)
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
	// At least 1.  Zero used to mean "ask on every request", and that second
	// meaning cost more than it bought: zero is also what an unset flag looks
	// like, so an operator who typed it got the install's old value back with
	// nothing said.  A second is indistinguishable from none in practice, and
	// the linked files are not on this clock at all -- the broker stats those
	// itself, per request.
	if out.MinRefreshSec, err = atLeast(sec, "min_refresh_sec", where, out.MinRefreshSec, 1); err != nil {
		return err
	}
	// Six, not one.  A shorter value is a matcher for something that occurs in
	// ordinary text, and at one character it rewrites every occurrence of that
	// character in every command's output.  The floor is low rather than high
	// because the two failures are not symmetric: a value refused here is absent
	// from the redactor and reaches output in the clear, while one matched too
	// eagerly only mangles the operator's own text.
	if out.MinLength, err = atLeast(sec, "min_length", where, out.MinLength, 6); err != nil {
		return err
	}
	return nil
}

// loadLinks validates every [[secret.link]] entry.  Checked at load rather than
// where the file is read, so a typo stops the daemon with its own name on it
// instead of surfacing later as a value the redactor turns out not to have.
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
		// refused rather than resolved: which of them won would be an
		// implementation detail of this loop.
		if seen[link.Ref] {
			return nil, fmt.Errorf("%s: ref %q is claimed by more than one entry; "+
				"a ref has one definition", at, link.Ref)
		}
		seen[link.Ref] = true
		out = append(out, link)
	}
	return out, nil
}

func validateLink(link Link, at string) error {
	// The same pattern a secret:// URI is parsed against.  A ref outside it would
	// load and then be unreachable, no caller being able to spell it.
	if link.Ref == "" {
		return fmt.Errorf("%s: ref is required; it is the name a caller asks by", at)
	}
	if !secretref.Valid(link.Ref) {
		return fmt.Errorf("%s: ref %q is not a name a secret:// reference can carry; "+
			"letters, digits, and then any of . _ - /", at, link.Ref)
	}
	if link.Path == "" {
		return fmt.Errorf("%s: path is required", at)
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
	// a whole-file link is an operator who believes something is being selected.
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

func loadApproval(raw map[string]any, path string, out *ApprovalConfig) error {
	where := path + ": [approval]"
	sec, err := table(raw, "approval", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, approvalKeys, where); err != nil {
		return err
	}
	// No exec_user by default, which is the install that granted no sudoers
	// entry: the rest describes where things would go if one ever did.
	*out = ApprovalConfig{
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-approve",
		// Nothing by default: `faramir approvals --watch` is where a question is seen
		// and answered, and a host that wants shouting about it as well says so.
		NotifyCommand: nil,
		TimeoutSec:    DefaultApprovalTimeoutSec,
	}
	if out.ExecUser, err = str(sec["exec_user"], where, ""); err != nil {
		return err
	}
	if out.PamService, err = str(sec["pam_service"], where, out.PamService); err != nil {
		return err
	}
	if out.Helper, err = str(sec["helper"], where, out.Helper); err != nil {
		return err
	}
	if out.NotifyCommand, err = stringList(sec["notify_command"], where, out.NotifyCommand); err != nil {
		return err
	}
	// An announcement that names neither the command nor the question is one
	// nobody can act on.  Empty is fine and is the default: it means the watcher
	// is the only place a question shows up.
	if len(out.NotifyCommand) > 0 && !slices.ContainsFunc(out.NotifyCommand, func(arg string) bool {
		return strings.Contains(arg, "{prompt}") || strings.Contains(arg, "{id}")
	}) {
		return fmt.Errorf("%s: notify_command names neither {prompt} nor {id}, so it "+
			"would announce that something is waiting without saying what", where)
	}
	// 0 would refuse every question the instant it was raised; the ceiling is what
	// keeps the broker the thing that decides.  See MaxSudoTimeoutSec.
	if out.TimeoutSec, err = intInRange(sec, "timeout_sec", where, out.TimeoutSec,
		1, MaxSudoTimeoutSec); err != nil {
		return fmt.Errorf("%w. A question is a human at a terminal and a host held "+
			"still while sudo waits on it, so this is bounded; past that, a refusal "+
			"and a second run is the better answer", err)
	}
	return nil
}

// MaxSudoTimeoutSec is the longest a question may wait for a human.
//
// It exists to keep one relationship true: the PAM helper's own deadline must
// outlast any question the broker will hold, or the helper would give up on a
// question still open and the operator's yes would land on a sudo that had
// already gone.  The helper cannot read this config: it runs from PAM with no
// environment and its argv is fixed at install time, and a value rendered into
// the service file would go stale the first time a drop-in changed it.  So it
// derives its deadline from this constant instead, and the two cannot drift.
//
// Ten minutes, which is generous for somebody at a terminal: the question is
// answered or refused within it, and while it is open sudo blocks and every
// other brokered command on the host is refused.  A host that wants longer wants
// a refusal and a second run.
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
