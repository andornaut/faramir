// Package config loads /etc/faramir/config.toml.
//
// Everything the broker will do is described there.  There is no command
// allowlist: the broker runs what it is asked to run, as a uid that holds
// nothing, and redacts the output.  See internal/resolve for why the allowlist
// was removed rather than merely widened.
//
// The file is decoded into a raw map and then hand-validated rather than
// unmarshalled straight into structs.  A mistyped key that is merely ignored
// leaves the config reading as though it had taken effect, so every section
// checks its key set and names the alternatives.
package config

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	DefaultConfigPath = "/etc/faramir/config.toml"
	defaultPATH       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// Error is a malformed or unsafe configuration.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errf(format string, args ...any) error { return &Error{msg: fmt.Sprintf(format, args...)} }

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// rejectUnknownKeys fails on a mistyped key, naming it and the alternatives.
func rejectUnknownKeys(raw map[string]any, known []string, where string) error {
	return rejectUnknown(raw, known, where, "key")
}

// rejectUnknownSections is the same check one level up, where the entries are
// [tables] rather than keys inside one.
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
	return errf("%s: unknown %s(s): %s; known %ss: %s",
		where, noun, strings.Join(unknown, ", "), noun, strings.Join(sorted, ", "))
}

// table returns one [section] as a map, rejecting a scalar written in its place.
func table(raw map[string]any, key, where string) (map[string]any, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return map[string]any{}, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errf("%s: expected a [%s] table, got %T", where, key, value)
	}
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out, nil
}

// octalMode accepts both "0660" and TOML's own 0o660.
//
// TOML parses 0o660 to the int 432, which is already the mode, so it is taken
// as-is; running it through a base-8 parse would reinterpret it as 0o432 --
// write for others, no read for the group -- without any error.
//
// The range check is what catches an unquoted decimal 660, a plausible typo
// for 0o660 that would otherwise mean 0o1224.  Every real mode fits in 0o777.
func octalMode(value any, where string) (os.FileMode, error) {
	switch v := value.(type) {
	case string:
		n, err := strconv.ParseInt(v, 8, 32)
		if err != nil {
			return 0, errf("%s: %q is not octal", where, v)
		}
		return rangeCheckMode(n, where)
	case int64:
		return rangeCheckMode(v, where)
	default:
		return 0, errf("%s: expected an octal string or integer", where)
	}
}

func rangeCheckMode(n int64, where string) (os.FileMode, error) {
	if n < 0 || n > 0o777 {
		return 0, errf("%s: out of range, expected 0 to 0o777; write the mode in "+
			`octal, as "0660" or 0o660`, where)
	}
	return os.FileMode(n), nil
}

func stringList(value any, where string, fallback []string) ([]string, error) {
	if value == nil {
		return fallback, nil
	}
	if s, ok := value.(string); ok {
		return nil, errf("%s: expected a list of strings, got string (write it as [%q])", where, s)
	}
	list, ok := value.([]any)
	if !ok {
		return nil, errf("%s: expected a list of strings, got %T", where, value)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, errf("%s: expected a string, got %T: %v", where, v, v)
		}
		out = append(out, s)
	}
	return out, nil
}

func intList(value any, where string, fallback []int) ([]int, error) {
	if value == nil {
		return fallback, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, errf("%s: expected a list of integers, got %T", where, value)
	}
	out := make([]int, 0, len(list))
	for _, v := range list {
		n, ok := v.(int64)
		if !ok {
			return nil, errf("%s: expected an integer, got %T: %v", where, v, v)
		}
		out = append(out, int(n))
	}
	return out, nil
}

func stringMap(value any, where string, fallback map[string]string) (map[string]string, error) {
	if value == nil {
		return fallback, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errf("%s: expected a table of strings, got %T", where, value)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, errf("%s: %s: expected a string, got %T", where, k, v)
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
		return "", errf("%s: expected a string, got %T", where, value)
	}
	return s, nil
}

func integer(value any, where string, fallback int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	n, ok := value.(int64)
	if !ok {
		return 0, errf("%s: expected an integer, got %T", where, value)
	}
	return int(n), nil
}

// intInRange is the value check the sizes and counts need.
//
// Checking key names but not their values leaves the same failure this file
// exists to prevent: a config that reads as though it had taken effect.  The
// out-of-range cases are not theoretical -- max_concurrency = -1 panics the
// broker on startup, max_concurrency = 0 refuses every request as busy, and
// default_timeout_sec = 0 kills every command the instant it starts.
func intInRange(sec map[string]any, key, where string, fallback, low, high int) (int, error) {
	n, err := integer(sec[key], where, fallback)
	if err != nil {
		return 0, err
	}
	if n < low || n > high {
		if high == maxInt {
			return 0, errf("%s: %s must be at least %d, got %d", where, key, low, n)
		}
		return 0, errf("%s: %s must be between %d and %d, got %d", where, key, low, high, n)
	}
	return n, nil
}

// atLeast is intInRange with no upper bound worth naming.
func atLeast(sec map[string]any, key, where string, fallback, low int) (int, error) {
	return intInRange(sec, key, where, fallback, low, maxInt)
}

const maxInt = int(^uint(0) >> 1)

func float(value any, where string, fallback float64) (float64, error) {
	if value == nil {
		return fallback, nil
	}
	switch v := value.(type) {
	case float64:
		return v, nil
	case int64:
		return float64(v), nil
	default:
		return 0, errf("%s: expected a number, got %T", where, value)
	}
}

// --------------------------------------------------------------------------
// Sections
// --------------------------------------------------------------------------

type ServerConfig struct {
	SocketPath      string
	SocketMode      os.FileMode
	MaxConcurrency  int
	MaxRequestBytes int
	AllowedUIDs     []int
	AllowedGroups   []string
	// MaxRedactsPerMin bounds the redact op per calling uid.  Zero is no limit.
	//
	// redact answers whether a piece of text holds a managed value, which makes
	// it an oracle: a caller that already knows part of a value can complete it
	// by asking.  Rating it does not close that -- nothing does, short of
	// removing the op -- but it turns an unmetered probe into one the operator
	// can see, at a ceiling no honest session reaches.
	MaxRedactsPerMin int
}

type ExecConfig struct {
	// No working directory here.  A brokered command runs where its caller
	// was, which every shipped caller sends; a directory named in a config
	// could only relocate a request that named none, and doing that silently
	// is surprising in exactly the case where it matters.
	DefaultTimeoutSec int
	MaxTimeoutSec     int
	MaxOutputBytes    int
	BaseEnv           map[string]string
	TermCols          int
	TermRows          int
	KillGraceSec      int
}

// KeeperConfig describes the process that holds the age key.
//
// Separate uid, separate socket, and no operation that returns the key.  The
// broker is the only client; AllowedUsers is what says so.
//
// No allowed_groups here.  It admitted every member of a named group, and the
// only group in play is dev, which holds the agent's own uid: the one
// value it could usefully take is the one that must never be set.
type KeeperConfig struct {
	SocketPath       string
	SocketMode       os.FileMode
	AllowedUsers     []string
	AgeKeyCredential string
	AgeKeyFile       string
}

// ExecutorConfig describes the process that forks brokered commands.
//
// Its uid holds nothing: no age key, no secret values, no audit log, no SSH
// keys.  A child forked by the broker instead would inherit all four.
type ExecutorConfig struct {
	SocketPath     string
	SocketMode     os.FileMode
	AllowedUsers   []string
	MaxConcurrency int
}

// SshConfig is an ssh-agent the broker owns, for keys the executor must not read.
//
// With no Keys no agent is started and nothing is injected; SSH then
// authenticates however the operator has arranged it for the executor's uid.
type SshConfig struct {
	Keys            []string
	AgentSocket     string
	AgentSocketMode os.FileMode
	ExecGroup       string
	SshAgent        string
	SshAdd          string
}

type SecretsConfig struct {
	Files []string
	// How the keeper invokes sops.  "{file}" is replaced with each managed
	// path.  sops is executed rather than linked: linking it would pull every
	// key source it supports into the process that holds the master key.
	DecryptCommand        []string
	RefreshIntervalSec    int
	MinLength             int
	MinUniqueChars        int
	MinEntropyBitsPerChar float64
}

// AuditConfig is the operator-only record of what the broker ran.
//
// It holds no secret value: output is recorded after redaction.  See
// internal/audit for why the unredacted copy went.
type AuditConfig struct {
	LogPath        string
	MaxRecordBytes int
}

type Config struct {
	Path string
	// Every file that contributed, base first, then each drop-in in the order
	// it was applied.  Reported by status and --check: "which files made this
	// config" is the first question when one does not say what an operator
	// expects.
	Sources  []string
	Server   ServerConfig
	Keeper   KeeperConfig
	Executor ExecutorConfig
	Exec     ExecConfig
	Ssh      SshConfig
	Secrets  SecretsConfig
	Audit    AuditConfig
}

// --------------------------------------------------------------------------
// Loading
// --------------------------------------------------------------------------

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

	// Drop-ins carry the settings that belong to whatever consumes the broker
	// rather than to the broker: which sops files to manage, which SSH key to
	// lend.  Keeping those out of the base file means the two have separate
	// owners and neither has to be merged by hand.
	dropIns, err := dropInPaths(filepath.Join(filepath.Dir(path), dropInDirName))
	if err != nil {
		return nil, err
	}
	sources := append([]string{path}, dropIns...)
	// Seeded from the base so a drop-in overriding a policy list is refused the
	// same way two drop-ins are: the base is a source like any other.
	setBy := map[string]string{}
	markTable(raw, "", path, setBy)
	for _, dropIn := range dropIns {
		layer, err := readTOML(dropIn)
		if err != nil {
			return nil, err
		}
		if err := mergeInto(raw, layer, "", dropIn, setBy); err != nil {
			return nil, err
		}
	}

	// Validated after merging, never before: a drop-in that sets
	// max_concurrency to 0 has to fail the same range check the base file
	// would, and an unknown key has to be refused wherever it was written.
	cfg, err := FromMap(raw, strings.Join(sources, ", "))
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	cfg.Sources = sources
	return cfg, nil
}

const dropInDirName = "config.d"

func readTOML(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errf("config not found: %s", path)
		}
		return nil, errf("%s: %v", path, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, errf("%s: %v", path, err)
	}
	return raw, nil
}

// dropInPaths lists *.toml in dir, in lexical order so a numeric prefix orders
// them.  A missing directory is the ordinary case and yields nothing.
//
// A directory that exists and cannot be read is an error rather than an empty
// list: a drop-in that should have applied and silently did not is a broker
// managing fewer files than its operator believes, which is the failure this
// package exists to make loud.
func dropInPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errf("%s: %v", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		// Dotfiles are skipped, not read: an editor writes its lock beside the
		// file as .#name.toml, a dangling symlink, and refusing that would stop
		// all three daemons starting for as long as a drop-in is open.
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".toml") {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// inventoryLists name what the broker is to manage, one entry per owner, so
// they accumulate across sources.  Everything else is policy.
//
// The distinction is the whole of the merge rule and it is not cosmetic.  These
// two grow: two projects each naming their own sops file both want theirs
// managed, and replacing would leave the broker holding fewer files than its
// operator believes, injecting nothing for the loser and redacting nothing
// either.  allowed_users, allowed_groups, allowed_uids and decrypt_command are
// the opposite: accumulating those would widen what the sockets admit, or what
// runs to decrypt, by writing a file that never said so.
var inventoryLists = map[string]bool{
	"secrets.files": true,
	"ssh.keys":      true,
}

// mergeInto layers one decoded config over another.
//
// Tables merge key by key, so a drop-in naming one [secrets] file does not
// discard min_length, and one adding a variable to [exec.base_env] does not
// have to restate PATH.  Scalars replace, which is what setting one means.
//
// Lists split by the rule above: an inventory accumulates, and any other list
// set by two sources is refused outright, naming both.  Silently taking the
// last would make a policy list depend on filename order.
//
// setBy records which source last set each dotted key, seeded from the base
// config, so the error can name the file an operator has to go and look at.
func mergeInto(base, layer map[string]any, prefix, source string, setBy map[string]string) error {
	for key, value := range layer {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}

		if sub, ok := value.(map[string]any); ok {
			if existing, ok := base[key].(map[string]any); ok {
				if err := mergeInto(existing, sub, full, source, setBy); err != nil {
					return err
				}
				continue
			}
			base[key] = value
			markTable(sub, full, source, setBy)
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
				return errf("%s: %s is set by both %s and %s. That list is policy "+
					"rather than an inventory, so it has one owner: name it in one "+
					"of them and not the other", source, full, prior, source)
			}
		}

		base[key] = value
		setBy[full] = source
	}
	return nil
}

// markTable records a whole subtree as having come from one source, for a table
// that replaced rather than merged.  Without it a later drop-in setting a list
// inside that table would look unset and overwrite it silently.
func markTable(sub map[string]any, prefix, source string, setBy map[string]string) {
	for key, value := range sub {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}
		if nested, ok := value.(map[string]any); ok {
			markTable(nested, full, source, setBy)
			continue
		}
		setBy[full] = source
	}
}

// appendNew adds what is not already there, so two owners naming the same file
// manage it once and the order stays the order it was contributed in.
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
	sections   = []string{"server", "keeper", "executor", "exec", "ssh", "secrets", "audit"}
	serverKeys = []string{"socket_path", "socket_mode", "max_concurrency",
		"max_request_bytes", "allowed_uids", "allowed_groups",
		"max_redacts_per_min"}
	keeperKeys = []string{"socket_path", "socket_mode", "allowed_users",
		"age_key_credential", "age_key_file"}
	executorKeys = []string{"socket_path", "socket_mode", "allowed_users",
		"max_concurrency"}
	execKeys = []string{"default_timeout_sec", "max_timeout_sec",
		"max_output_bytes", "base_env", "term_cols", "term_rows", "kill_grace_sec"}
	sshKeys = []string{"keys", "agent_socket", "agent_socket_mode", "exec_group",
		"ssh_agent", "ssh_add"}
	secretsKeys = []string{"files", "decrypt_command", "refresh_interval_sec",
		"min_length", "min_unique_chars", "min_entropy_bits_per_char"}
	auditKeys = []string{"log_path", "max_record_bytes"}
)

func FromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

	// A mistyped section is as silent as a mistyped key, and worse: [secret]
	// for [secrets] leaves a broker that manages no files and redacts nothing.
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
	if err := loadAudit(raw, path, &cfg.Audit); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadServer(raw map[string]any, path string, out *ServerConfig) error {
	where := fmt.Sprintf("%s: [server]", path)
	sec, err := table(raw, "server", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, serverKeys, where); err != nil {
		return err
	}
	*out = ServerConfig{
		SocketPath:     "/run/faramir/broker.sock",
		SocketMode:     0o660,
		MaxConcurrency: 4, MaxRequestBytes: 262144,
		AllowedGroups: []string{"dev"}, MaxRedactsPerMin: 240,
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	if v, ok := sec["socket_mode"]; ok {
		if out.SocketMode, err = octalMode(v, fmt.Sprintf("%s: server.socket_mode", path)); err != nil {
			return err
		}
	}
	// 1, not 0: make(chan, 0) is unbuffered, so the non-blocking slot grab in
	// the broker always falls through and every request is refused as busy.
	if out.MaxConcurrency, err = atLeast(sec, "max_concurrency", where, out.MaxConcurrency, 1); err != nil {
		return err
	}
	if out.MaxRequestBytes, err = atLeast(sec, "max_request_bytes", where, out.MaxRequestBytes, 1); err != nil {
		return err
	}
	if out.AllowedUIDs, err = intList(sec["allowed_uids"], where, nil); err != nil {
		return err
	}
	if out.AllowedGroups, err = stringList(sec["allowed_groups"], where, out.AllowedGroups); err != nil {
		return err
	}
	// Zero is legal and means no limit, so atLeast(0) rather than atLeast(1).
	if out.MaxRedactsPerMin, err = atLeast(sec, "max_redacts_per_min", where,
		out.MaxRedactsPerMin, 0); err != nil {
		return err
	}
	return nil
}

func loadKeeper(raw map[string]any, path string, out *KeeperConfig) error {
	where := fmt.Sprintf("%s: [keeper]", path)
	sec, err := table(raw, "keeper", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, keeperKeys, where); err != nil {
		return err
	}
	*out = KeeperConfig{
		SocketPath: "/run/faramir/keeper.sock", SocketMode: 0o660,
		AllowedUsers: []string{"faramir-broker"}, AgeKeyCredential: "age_key",
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	if v, ok := sec["socket_mode"]; ok {
		if out.SocketMode, err = octalMode(v, fmt.Sprintf("%s: keeper.socket_mode", path)); err != nil {
			return err
		}
	}
	if out.AllowedUsers, err = stringList(sec["allowed_users"], where, out.AllowedUsers); err != nil {
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
	where := fmt.Sprintf("%s: [executor]", path)
	sec, err := table(raw, "executor", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, executorKeys, where); err != nil {
		return err
	}
	*out = ExecutorConfig{
		SocketPath: "/run/faramir/exec.sock", SocketMode: 0o660,
		AllowedUsers: []string{"faramir-broker"}, MaxConcurrency: 16,
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	if v, ok := sec["socket_mode"]; ok {
		if out.SocketMode, err = octalMode(v, fmt.Sprintf("%s: executor.socket_mode", path)); err != nil {
			return err
		}
	}
	if out.AllowedUsers, err = stringList(sec["allowed_users"], where, out.AllowedUsers); err != nil {
		return err
	}
	if out.MaxConcurrency, err = atLeast(sec, "max_concurrency", where, out.MaxConcurrency, 1); err != nil {
		return err
	}
	return nil
}

func loadExec(raw map[string]any, path string, out *ExecConfig) error {
	where := fmt.Sprintf("%s: [exec]", path)
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
	// A timeout of 0 is not "no limit": the executor arms a timer with it and
	// SIGTERMs the child the instant it starts, with no output and no clue why.
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
	// The winsize ioctl takes uint16s, so a larger value wraps silently.
	if out.TermCols, err = intInRange(sec, "term_cols", where, out.TermCols, 1, 65535); err != nil {
		return err
	}
	if out.TermRows, err = intInRange(sec, "term_rows", where, out.TermRows, 1, 65535); err != nil {
		return err
	}
	// 0 is meaningful here: SIGKILL immediately after SIGTERM.
	if out.KillGraceSec, err = atLeast(sec, "kill_grace_sec", where, out.KillGraceSec, 0); err != nil {
		return err
	}
	// Optional, and unset is the better setting.  A brokered command runs where
	// its caller was, the way every other command does: the CLI and the MCP
	// Every request is clamped to max_timeout_sec, so a smaller one here does
	// not cap default_timeout_sec, it replaces it.
	if out.MaxTimeoutSec < out.DefaultTimeoutSec {
		return errf("%s: [exec] max_timeout_sec (%d) is below default_timeout_sec "+
			"(%d), which would silently override it for every command",
			path, out.MaxTimeoutSec, out.DefaultTimeoutSec)
	}
	return nil
}

func loadSecrets(raw map[string]any, path string, out *SecretsConfig) error {
	where := fmt.Sprintf("%s: [secrets]", path)
	sec, err := table(raw, "secrets", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, secretsKeys, where); err != nil {
		return err
	}
	*out = SecretsConfig{
		DecryptCommand:     []string{"sops", "--output-type", "json", "--decrypt", "{file}"},
		RefreshIntervalSec: 5, MinLength: 8, MinUniqueChars: 4,
		MinEntropyBitsPerChar: 1.5,
	}
	if out.Files, err = stringList(sec["files"], where, nil); err != nil {
		return err
	}
	// Each entry is a glob pattern, a literal path being one with no
	// metacharacters.  Checked here because a malformed pattern matches nothing
	// at every later stage, and "matched no files" would send the operator
	// looking for a store that is exactly where they left it.  Match against the
	// empty string touches no filesystem and reports only ErrBadPattern.
	for _, pattern := range out.Files {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return errf("%s: files entry %q is not a valid glob pattern: %v",
				where, pattern, err)
		}
	}
	if out.DecryptCommand, err = stringList(sec["decrypt_command"], where, out.DecryptCommand); err != nil {
		return err
	}
	// 0 is meaningful: check on every request.
	if out.RefreshIntervalSec, err = atLeast(sec, "refresh_interval_sec", where, out.RefreshIntervalSec, 0); err != nil {
		return err
	}
	// 1, not 0: a zero-length value passes the gate and compiles to a matcher
	// for the empty string's quoted form, which would rewrite unrelated output.
	if out.MinLength, err = atLeast(sec, "min_length", where, out.MinLength, 1); err != nil {
		return err
	}
	if out.MinUniqueChars, err = atLeast(sec, "min_unique_chars", where, out.MinUniqueChars, 1); err != nil {
		return err
	}
	if out.MinEntropyBitsPerChar, err = float(sec["min_entropy_bits_per_char"], where, out.MinEntropyBitsPerChar); err != nil {
		return err
	}
	if out.MinEntropyBitsPerChar < 0 {
		return errf("%s: min_entropy_bits_per_char must not be negative, got %v",
			where, out.MinEntropyBitsPerChar)
	}
	return nil
}

func loadSsh(raw map[string]any, path string, out *SshConfig) error {
	where := fmt.Sprintf("%s: [ssh]", path)
	sec, err := table(raw, "ssh", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, sshKeys, where); err != nil {
		return err
	}
	*out = SshConfig{
		AgentSocket: "/run/faramir/ssh-agent.sock", AgentSocketMode: 0o660,
		ExecGroup: "faramir-exec", SshAgent: "/usr/bin/ssh-agent", SshAdd: "/usr/bin/ssh-add",
	}
	if out.Keys, err = stringList(sec["keys"], where, nil); err != nil {
		return err
	}
	if out.AgentSocket, err = str(sec["agent_socket"], where, out.AgentSocket); err != nil {
		return err
	}
	if v, ok := sec["agent_socket_mode"]; ok {
		if out.AgentSocketMode, err = octalMode(v, fmt.Sprintf("%s: ssh.agent_socket_mode", path)); err != nil {
			return err
		}
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

func loadAudit(raw map[string]any, path string, out *AuditConfig) error {
	where := fmt.Sprintf("%s: [audit]", path)
	sec, err := table(raw, "audit", path)
	if err != nil {
		return err
	}
	if err := rejectUnknownKeys(sec, auditKeys, where); err != nil {
		return err
	}
	*out = AuditConfig{LogPath: "/var/log/faramir/audit.log", MaxRecordBytes: 4194304}
	if out.LogPath, err = str(sec["log_path"], where, out.LogPath); err != nil {
		return err
	}
	if out.MaxRecordBytes, err = atLeast(sec, "max_record_bytes", where, out.MaxRecordBytes, 1); err != nil {
		return err
	}
	return nil
}
