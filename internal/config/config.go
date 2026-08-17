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

// intInRange is the value check the sizes and counts need: max_concurrency = -1
// panics on startup, 0 refuses every request as busy, and default_timeout_sec =
// 0 kills every command as it starts.
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
	SocketPath      string
	MaxConcurrency  int
	MaxRequestBytes int
	AllowedGroup    string
}

type ExecConfig struct {
	// No working directory here: a brokered command runs where its caller was.
	DefaultTimeoutSec int
	MaxTimeoutSec     int
	MaxOutputBytes    int
	BaseEnv           map[string]string
	TermCols          int
	TermRows          int
	KillGraceSec      int
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
// No max_concurrency.  The broker is the only client this socket admits and it
// holds one [server] max_concurrency slot for the whole of each child, so that
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

// SudoConfig is how a brokered command becomes root on this host: it does not
// authenticate, it asks.  With no ExecUser nothing is granted and no question
// can be raised, which is the install that never passed --allow-sudo.
// Everything here but TimeoutSec is init's, each value naming a file or a
// program that decides whether an approval happens.
type SudoConfig struct {
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

type SecretsConfig struct {
	// Patterns is the managed sops files as globs, which is what the entries are:
	// each is matched against the secrets directory rather than opened by name.
	// The --check report calls the paths they resolve to "files", so the two words
	// stay distinct there.
	Patterns []string
	// How the keeper invokes sops; "{file}" is each managed path.  Executed rather
	// than linked, which would pull every key source sops supports into the
	// process holding the master key.
	DecryptCommand     []string
	RefreshIntervalSec int
	MinLength          int
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
	// MaxRecordBytes is the largest one record's line may be, counted in the
	// bytes the line spends once encoded rather than in the bytes a command
	// wrote: '<', '>', '&' and every C0 control cost six apiece as JSON, so a cap
	// counted before encoding is a cap the command chooses the meaning of.
	//
	// internal/audit holds a record to it whatever it is handed, excerpting the
	// output to the head and the tail of a run and cutting every other field if
	// that is not enough, so a reader needs no ceiling of its own.
	MaxRecordBytes int
}

// MinRecordBytes floors [AuditConfig.MaxRecordBytes].  A record has an identity
// even when everything else has been cut away -- the log_id, the op and the
// caller -- and a cap below that would ask internal/audit to write a line it has
// no room for.
const MinRecordBytes = 4096

type Config struct {
	Path string
	// Every file that contributed, base first then each drop-in in order. Reported
	// by status and --check.
	Sources  []string
	Server   ServerConfig
	Keeper   KeeperConfig
	Executor ExecutorConfig
	Exec     ExecConfig
	Ssh      SshConfig
	Sudo     SudoConfig
	Secrets  SecretsConfig
	Audit    AuditConfig
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("FARAMIR_CONFIG")
	}
	if path == "" {
		path = DefaultConfigPath
	}
	base, err := readTOML(path)
	if err != nil {
		return nil, err
	}

	// Drop-ins carry what belongs to whatever consumes the broker (which sops
	// files to manage, which SSH key to lend), so the two have separate owners.
	dropIns, err := dropInPaths(filepath.Join(filepath.Dir(path), dropInDirName))
	if err != nil {
		return nil, err
	}
	sources := append([]string{path}, dropIns...)
	// The base is merged like any other source rather than merged into, so setBy
	// records it as the owner of what it set.
	raw := map[string]any{}
	setBy := map[string]string{}
	for i, source := range sources {
		layer := base
		if i > 0 {
			if layer, err = readTOML(source); err != nil {
				return nil, err
			}
		}
		if err := mergeInto(raw, layer, "", source, i > 0, setBy); err != nil {
			return nil, err
		}
	}

	// After merging, so a drop-in faces the same checks the base file does.
	cfg, err := fromMap(raw, strings.Join(sources, ", "))
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	cfg.Sources = sources
	return cfg, nil
}

// BaseLinks is the [[secrets.link]] entries in one file, with no drop-in
// merged over it.
//
// The base file alone, and that is the whole point of the function.  init
// renders the links it manages back into config.toml, so if it read the merged
// view a link written in a drop-in would be copied into the base file and then
// refused on the next load as two entries claiming one ref.  A link a drop-in
// declares stays the drop-in's; `faramir link` owns the ones in config.toml.
//
// A file that is not there yields nothing, which is a first install.
func BaseLinks(path string) ([]Link, error) {
	raw, err := readTOML(path)
	if err != nil {
		if os.IsNotExist(err) || strings.HasPrefix(err.Error(), "config not found") {
			return nil, nil
		}
		return nil, err
	}
	sec, err := table(raw, "secrets", path)
	if err != nil {
		return nil, err
	}
	return loadLinks(sec["link"], path+": [secrets]")
}

// ValidateLink holds one entry to what the loader would accept, for a command
// that builds one before anything writes it.
func ValidateLink(link Link) error { return validateLink(link, "[[secrets.link]]") }

const dropInDirName = "config.d"

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

// dropInPaths lists *.toml in dir, lexically, so a numeric prefix orders them.
// A missing directory yields nothing; one that cannot be read is an error,
// since a drop-in that silently did not apply is a broker managing fewer files
// than its operator believes.
func dropInPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		// Skipped, not read: an editor's lock is a dangling .#name.toml symlink, and
		// refusing it would stop the daemons while a drop-in is open.
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".toml") {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// inventoryLists name what the broker is to manage, one entry per owner, so
// they accumulate across sources.  Everything else is policy and replaces:
// accumulating decrypt_command would hand the keeper a second way to invoke
// sops by writing a file that never said so.
var inventoryLists = map[string]bool{
	"secrets.patterns": true,
}

// linkList is the other inventory, and the only array of tables in the file.
// Handled apart from inventoryLists because TOML decodes an array of tables as
// []map[string]any rather than []any, so it reaches neither list branch, and
// because its entries are deduplicated by ref rather than by equality.
const linkList = "secrets.link"

// noFlagResolved marks a key init works out at install time rather than taking
// from a flag.  A sentinel rather than prose, so the remedy is matched exactly:
// a near-miss would fall through to the build-time wording, which is the one
// answer that sends an operator away from what would have changed the value.
const noFlagResolved = "\x00resolved-at-install"

// initOwned are the keys init derives from a flag or from the install layout,
// which a drop-in may not set.  The rule that decides membership: a key init
// computes is init's, and a key it writes as a plain default is a starting
// point the operator may change.  Everything not here is the second kind.
//
// Distinct from systemdOwned, which is what the .socket units decide.
//
// All but sudo.notify_command are scalars, which the policy rule below cannot
// reach: that one refuses a list two sources set, and a scalar simply replaces.
// This check runs first either way.  ssh.exec_group is what makes this matter
// rather than being tidiness, being the group the ssh-agent relay's SO_PEERCRED
// check admits; a drop-in naming the client group there hands the broker's SSH
// identity to the account the relay exists to keep it from.
//
// The value is the flag that sets each, so the refusal says what to run
// instead.  Three forms: a flag, noFlagResolved for a value init works out at
// install time, and empty for one rendered from a path fixed at build time that
// no flag moves.  TestEveryInitOwnedRemedyIsReachable holds every form to being
// produced by some key, a form nothing reaches being a refusal that cannot
// route.
//
// The distinction is the whole point of saying anything: an operator told "no
// flag moves this" about a value init resolves on PATH has been sent away from
// the one thing that would have changed it.
var initOwned = map[string]string{
	// A second identity reaches the same hosts and is one no account has ever
	// held; a key of your own is adopted rather than replaced.
	"ssh.key": "--ssh-key PATH",
	// What each socket admits.
	"server.allowed_group":  "--client-group NAME",
	"keeper.allowed_user":   "--broker-user NAME",
	"executor.allowed_user": "--broker-user NAME",
	// The exec account's primary group, resolved at install time.
	"ssh.exec_group": "--exec-user NAME",
	// The whole of [sudo] but timeout_sec.  Every one of these decides whether
	// an approval happens rather than being a default to tune: pam_service names
	// the file sudo authenticates that account against, helper is the program that
	// file execs as root, notify_command is a program the broker execs as the uid
	// holding every plaintext value, and exec_user is the account the whole grant
	// is written for.  Who may *answer* is not here, being no config key at all:
	// it is root, checked with SO_PEERCRED, and nothing can widen it.
	"sudo.exec_user":      "--allow-sudo",
	"sudo.pam_service":    "",
	"sudo.helper":         "",
	"sudo.notify_command": "--allow-sudo --notify-command PROGRAM --notify-command ARG",
	// Where the master key is read from, and the credential the keeper unit
	// supplies it under, which that unit renders alongside.
	"keeper.age_key_file":       "--config-dir PATH",
	"keeper.age_key_credential": "",
	// The binaries the broker execs as the uid holding every plaintext value. init
	// resolves them on PATH; a drop-in pointing either elsewhere is code execution
	// as that uid.
	//
	// Resolved rather than fixed, so the remedy is a re-run and not "no flag moves
	// this": what init finds on PATH is what these become, and an operator who
	// wants another ssh-agent installs it and runs init again.
	"ssh.ssh_agent": noFlagResolved,
	"ssh.ssh_add":   noFlagResolved,
	// From LogDir and RunDir.  audit.log_path is rendered into logrotate.conf
	// beside it, and the agent socket into the unit's RuntimeDirectory, so moving
	// one here leaves the other pointed where it was.
	"audit.log_path":   "",
	"ssh.agent_socket": "",
}

// systemdOwned are the keys the .socket units decide, which a drop-in may not
// set.
//
// The daemons are handed a listening descriptor and never reach the bind path,
// so these describe a socket rather than choose it, and init renders both sides
// together.  They are not uniformly inert, though: the broker dials the keeper
// and the executor at the path named here, so a drop-in setting [keeper]
// socket_path moves nothing and breaks the broker's own connection, surfacing
// as "keeper unreachable".
//
// Refused in a drop-in rather than everywhere: the base file is init's to write
// and has to carry them, and a broker run outside systemd binds them itself.
var systemdOwned = map[string]bool{
	"server.socket_path":   true,
	"keeper.socket_path":   true,
	"executor.socket_path": true,
}

// mergeInto layers one decoded config over another.  Tables merge key by key
// and scalars replace.  Lists split by the rule above: an inventory
// accumulates, and any other list set by two sources is refused, naming both.
// setBy records which source last set each dotted key, for that error.
//
// dropIn is false for the base file alone, which carries the keys init renders
// and systemd overrides.
func mergeInto(base, layer map[string]any, prefix, source string, dropIn bool, setBy map[string]string) error {
	for key, value := range layer {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}

		if dropIn && systemdOwned[full] {
			return fmt.Errorf("%s: %s is set by the .socket unit, not by this file, so "+
				"setting it here moves nothing. Worse, the broker dials the keeper "+
				"and the executor at the path named here, so an edit breaks its own "+
				"connection to a daemon still listening where it was. Change it with "+
				"`faramir init` and let it rewrite both sides", source, full)
		}

		if dropIn {
			if flag, owned := initOwned[full]; owned {
				remedy := "It is rendered from a path fixed at build time, which no flag moves"
				switch {
				case flag == noFlagResolved:
					remedy = "No flag names it: init resolves it on PATH at install time, so " +
						"install what you want it to find and re-run `faramir init`"
				case flag != "":
					remedy = "Change it with `faramir init " + flag + "`"
				}
				return fmt.Errorf("%s: %s is init's, not this file's: it derives from "+
					"the install rather than being a default to tune, and init rewrites "+
					"it every run. %s", source, full, remedy)
			}
		}

		if sub, ok := value.(map[string]any); ok {
			// A table always merges into a table, one being created when the base has
			// none.  Replacing wholesale left every key inside it unmarked in setBy, so
			// a later drop-in setting a policy list in there looked unset and overwrote
			// it silently; recursing into an empty map marks them on the way through
			// instead.
			existing, ok := base[key].(map[string]any)
			if !ok {
				existing = map[string]any{}
				base[key] = existing
			}
			if err := mergeInto(existing, sub, full, source, dropIn, setBy); err != nil {
				return err
			}
			continue
		}

		if entries, ok := value.([]map[string]any); ok && full == linkList {
			existing, _ := base[key].([]map[string]any)
			merged, err := appendLinks(existing, entries, source, setBy)
			if err != nil {
				return err
			}
			base[key] = merged
			continue
		}

		if list, ok := value.([]any); ok {
			if inventoryLists[full] {
				existing, _ := base[key].([]any)
				base[key] = appendNew(existing, list)
				setBy[full] = source
				continue
			}
			if prior, seen := setBy[full]; seen {
				return fmt.Errorf("%s: %s is set by both %s and %s. That list is policy "+
					"rather than an inventory, so it has one owner: name it in one "+
					"of them and not the other", source, full, prior, source)
			}
		}

		base[key] = value
		setBy[full] = source
	}
	return nil
}

// appendLinks accumulates [[secrets.link]] entries across sources, refusing two
// that claim one ref.  An inventory like patterns, with one difference: a ref is
// the name a caller asks by, so two definitions are not a duplicate to collapse
// but a question of which file wins, and that would come down to filename order.
func appendLinks(existing, incoming []map[string]any, source string,
	setBy map[string]string) ([]map[string]any, error) {
	out := append([]map[string]any{}, existing...)
	for _, entry := range incoming {
		// A ref that is absent or not a string is loadLinks' to report, which names
		// the entry and the reason.  Here it only has to not collide.
		ref, _ := entry["ref"].(string)
		if ref != "" {
			marker := linkList + ":" + ref
			if prior, seen := setBy[marker]; seen {
				return nil, fmt.Errorf("%s: two [[secrets.link]] entries claim ref %q, one "+
					"in %s and one in %s. A ref is the name a caller asks by, so it has "+
					"one definition: name it in one of them and not the other",
					source, ref, prior, source)
			}
			setBy[marker] = source
		}
		out = append(out, entry)
	}
	return out, nil
}

// appendNew adds what is not already there, preserving contribution order.
func appendNew(existing, incoming []any) []any {
	seen := make(map[any]bool, len(existing))
	out := make([]any, 0, len(existing)+len(incoming))
	for _, v := range existing {
		seen[v] = true
		out = append(out, v)
	}
	for _, v := range incoming {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

var (
	sections = []string{"server", "keeper", "executor", "exec", "ssh", "sudo",
		"secrets", "audit"}
	serverKeys = []string{"socket_path", "max_concurrency",
		"max_request_bytes", "allowed_group"}
	keeperKeys = []string{"socket_path", "allowed_user",
		"age_key_credential", "age_key_file"}
	executorKeys = []string{"socket_path", "allowed_user"}
	execKeys     = []string{"default_timeout_sec", "max_timeout_sec",
		"max_output_bytes", "base_env", "term_cols", "term_rows", "kill_grace_sec"}
	sshKeys = []string{"key", "agent_socket", "exec_group",
		"ssh_agent", "ssh_add"}
	sudoKeys = []string{"exec_user", "pam_service", "helper",
		"notify_command", "timeout_sec"}
	secretsKeys = []string{"patterns", "decrypt_command", "refresh_interval_sec",
		"min_length", "link"}
	linkKeys  = []string{"ref", "path", "type", "key"}
	auditKeys = []string{"log_path", "max_record_bytes"}
)

func fromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

	// [secret] for [secrets] leaves a broker managing no files.
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
	if err := loadExec(raw, path, &cfg.Exec); err != nil {
		return nil, err
	}
	if err := loadSecrets(raw, path, &cfg.Secrets); err != nil {
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
		SocketPath:     "/run/faramir/broker.sock",
		MaxConcurrency: 10, MaxRequestBytes: 262144,
		AllowedGroup: "dev",
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	// 1, not 0: an unbuffered channel refuses every request as busy.
	if out.MaxConcurrency, err = atLeast(sec, "max_concurrency", where, out.MaxConcurrency, 1); err != nil {
		return err
	}
	if out.MaxRequestBytes, err = atLeast(sec, "max_request_bytes", where, out.MaxRequestBytes, 1); err != nil {
		return err
	}
	if out.AllowedGroup, err = str(sec["allowed_group"], where, out.AllowedGroup); err != nil {
		return err
	}
	// Zero means no limit.
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

func loadExec(raw map[string]any, path string, out *ExecConfig) error {
	where := path + ": [exec]"
	sec, err := table(raw, "exec", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, execKeys, where); err != nil {
		return err
	}
	*out = ExecConfig{
		DefaultTimeoutSec: 600, MaxTimeoutSec: 3600, MaxOutputBytes: 1048576,
		BaseEnv: map[string]string{
			"PATH": defaultPATH, "TERM": "xterm-256color", "LANG": "C.UTF-8",
			"LC_ALL": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive",
		},
		TermCols: 120, TermRows: 40, KillGraceSec: 5,
	}
	// 0 is not "no limit": it SIGTERMs the child the instant it starts.
	if out.DefaultTimeoutSec, err = atLeast(sec, "default_timeout_sec", where, out.DefaultTimeoutSec, 1); err != nil {
		return err
	}
	if out.MaxTimeoutSec, err = atLeast(sec, "max_timeout_sec", where, out.MaxTimeoutSec, 1); err != nil {
		return err
	}
	if out.MaxOutputBytes, err = atLeast(sec, "max_output_bytes", where, out.MaxOutputBytes, 1); err != nil {
		return err
	}
	if out.BaseEnv, err = stringMap(sec["base_env"], where, out.BaseEnv); err != nil {
		return err
	}
	// The winsize ioctl takes uint16s, so more wraps silently.
	if out.TermCols, err = intInRange(sec, "term_cols", where, out.TermCols, 1, 65535); err != nil {
		return err
	}
	if out.TermRows, err = intInRange(sec, "term_rows", where, out.TermRows, 1, 65535); err != nil {
		return err
	}
	// 0 means SIGKILL immediately after SIGTERM.
	if out.KillGraceSec, err = atLeast(sec, "kill_grace_sec", where, out.KillGraceSec, 0); err != nil {
		return err
	}
	// PATH decides which file a bare cmd[0] resolves to, and it is resolved by the
	// broker on behalf of a child that runs somewhere else.  A component a shell
	// would read as its working directory is therefore two different directories
	// here, so it is refused at load rather than skipped at resolve time: the
	// broker does not start, instead of running a file nobody named.
	// A base_env in the file replaces the built-in one rather than adding to it,
	// so a table that omits PATH leaves the broker resolving no bare name at all.
	// Named separately from the check below, which would report the same empty
	// string as a component nobody wrote.
	if out.BaseEnv["PATH"] == "" {
		return fmt.Errorf("%s: [exec] base_env sets no PATH, so no bare program name "+
			"resolves. Setting base_env replaces the built-in table rather than adding "+
			"to it, so it has to name PATH itself; `faramir init` writes it as %q",
			path, defaultPATH)
	}
	for component := range strings.SplitSeq(out.BaseEnv["PATH"], ":") {
		if filepath.IsAbs(component) {
			continue
		}
		shown := component
		if shown == "" {
			shown = "an empty component"
		}
		return fmt.Errorf("%s: [exec] base_env PATH contains %s, which means the "+
			"working directory. The broker resolves a bare program name from its own "+
			"directory and the command runs in the request's, so the file checked "+
			"would not be the file run. Name every directory absolutely", path, shown)
	}
	// Every request is clamped to max_timeout_sec, so a smaller one here would
	// replace default_timeout_sec rather than cap it.
	if out.MaxTimeoutSec < out.DefaultTimeoutSec {
		return fmt.Errorf("%s: [exec] max_timeout_sec (%d) is below default_timeout_sec "+
			"(%d), which would silently override it for every command",
			path, out.MaxTimeoutSec, out.DefaultTimeoutSec)
	}
	return nil
}

func loadSecrets(raw map[string]any, path string, out *SecretsConfig) error {
	where := path + ": [secrets]"
	sec, err := table(raw, "secrets", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, secretsKeys, where); err != nil {
		return err
	}
	*out = SecretsConfig{
		DecryptCommand:     []string{"sops", "--output-type", "json", "--decrypt", "{file}"},
		RefreshIntervalSec: 5, MinLength: 8,
	}
	if out.Patterns, err = stringList(sec["patterns"], where, nil); err != nil {
		return err
	}
	// Each entry is a glob pattern; a malformed one matches nothing at every later
	// stage, reading as a missing store.  Matching the empty string touches no
	// filesystem and reports only ErrBadPattern.
	for _, pattern := range out.Patterns {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("%s: patterns entry %q is not a valid glob pattern: %w",
				where, pattern, err)
		}
	}
	if out.Links, err = loadLinks(sec["link"], where); err != nil {
		return err
	}
	if out.DecryptCommand, err = stringList(sec["decrypt_command"], where, out.DecryptCommand); err != nil {
		return err
	}
	// 0 means check on every request.
	if out.RefreshIntervalSec, err = atLeast(sec, "refresh_interval_sec", where, out.RefreshIntervalSec, 0); err != nil {
		return err
	}
	// 1, not 0: a zero-length value would compile to a matcher for the empty
	// string and rewrite unrelated output.
	if out.MinLength, err = atLeast(sec, "min_length", where, out.MinLength, 1); err != nil {
		return err
	}
	return nil
}

// loadLinks validates every [[secrets.link]] entry.  Checked at load rather than
// where the file is read, so a typo stops the daemon with its own name on it
// instead of surfacing later as a value the redactor turns out not to have.
func loadLinks(value any, where string) ([]Link, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected [[secrets.link]] tables, got %T "+
			"(write each entry as its own [[secrets.link]] header)", where, value)
	}
	out := make([]Link, 0, len(entries))
	for i, entry := range entries {
		at := fmt.Sprintf("%s: [[secrets.link]] #%d", where, i+1)
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

func loadSudo(raw map[string]any, path string, out *SudoConfig) error {
	where := path + ": [sudo]"
	sec, err := table(raw, "sudo", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, sudoKeys, where); err != nil {
		return err
	}
	// No exec_user by default, which is the install that granted no sudoers
	// entry: the rest describes where things would go if one ever did.
	*out = SudoConfig{
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-approve",
		// Nothing by default: `faramir approvals --watch` is where a question is seen
		// and answered, and a host that wants shouting about it as well says so.
		NotifyCommand: nil,
		TimeoutSec:    120,
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
	*out = AuditConfig{LogPath: "/var/log/faramir/audit.log", MaxRecordBytes: 1048576}
	if out.LogPath, err = str(sec["log_path"], where, out.LogPath); err != nil {
		return err
	}
	if out.MaxRecordBytes, err = atLeast(sec, "max_record_bytes", where, out.MaxRecordBytes, MinRecordBytes); err != nil {
		return err
	}
	return nil
}
