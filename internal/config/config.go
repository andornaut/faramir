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

// octalMode accepts both "0660" and TOML's own 0o660.  An int is already the
// mode, so a base-8 parse would reinterpret it silently.  The range check
// catches an unquoted decimal 660, which would mean 0o1224.
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

// intInRange is the value check the sizes and counts need: max_concurrency = -1
// panics on startup, 0 refuses every request as busy, and
// default_timeout_sec = 0 kills every command as it starts.
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

// ServerConfig describes the broker's own socket, the one an operator reaches.
//
// Callers are named by group rather than by uid.  A uid list was a second
// spelling of the same answer that stopped being true the moment an account was
// renumbered, and nothing asked it a question allowed_groups could not.
type ServerConfig struct {
	SocketPath      string
	SocketMode      os.FileMode
	MaxConcurrency  int
	MaxRequestBytes int
	AllowedGroups   []string
	// MaxRedactsPerMin bounds the redact op per calling uid.  Zero is no limit.
	// It does not close the oracle, only make a probe visible.
	MaxRedactsPerMin int
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
// client, which AllowedUsers says.  No allowed_groups, because the only group
// in play holds the agent's own uid.
type KeeperConfig struct {
	SocketPath       string
	SocketMode       os.FileMode
	AllowedUsers     []string
	AgeKeyCredential string
	AgeKeyFile       string
}

// ExecutorConfig describes the process that forks brokered commands.  Its uid
// holds no age key, values, audit log or SSH keys; a child forked by the broker
// would inherit all four.
type ExecutorConfig struct {
	SocketPath     string
	SocketMode     os.FileMode
	AllowedUsers   []string
	MaxConcurrency int
}

// SshConfig is an ssh-agent the broker owns, for keys the executor must not
// read.  With no Keys no agent is started, and SSH authenticates however the
// operator arranged it for the executor's uid.
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
	// How the keeper invokes sops; "{file}" is each managed path.  Executed
	// rather than linked, which would pull every key source sops supports into
	// the process holding the master key.
	DecryptCommand        []string
	RefreshIntervalSec    int
	MinLength             int
	MinUniqueChars        int
	MinEntropyBitsPerChar float64
}

// AuditConfig is the operator-only record of what the broker ran.  Output is
// recorded after redaction, so it holds no value.
type AuditConfig struct {
	LogPath        string
	MaxRecordBytes int
}

type Config struct {
	Path string
	// Every file that contributed, base first then each drop-in in order.
	// Reported by status and --check.
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
	base, err := readTOML(path)
	if err != nil {
		return nil, err
	}

	// Drop-ins carry what belongs to whatever consumes the broker -- which sops
	// files to manage, which SSH key to lend -- so the two have separate
	// owners.
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
		if err := mergeInto(raw, layer, "", source, setBy); err != nil {
			return nil, err
		}
	}

	// After merging, so a drop-in faces the same checks the base file does.
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
		return nil, errf("%s: %v", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		// Skipped, not read: an editor's lock is a dangling .#name.toml symlink,
		// and refusing it would stop the daemons while a drop-in is open.
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
// accumulating allowed_users, allowed_groups or decrypt_command would widen
// what the sockets admit by writing a file that never said so.
var inventoryLists = map[string]bool{
	"secrets.files": true,
	"ssh.keys":      true,
}

// mergeInto layers one decoded config over another.  Tables merge key by key
// and scalars replace.  Lists split by the rule above: an inventory
// accumulates, and any other list set by two sources is refused, naming both.
// setBy records which source last set each dotted key, for that error.
func mergeInto(base, layer map[string]any, prefix, source string, setBy map[string]string) error {
	for key, value := range layer {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}

		if sub, ok := value.(map[string]any); ok {
			// A table always merges into a table, one being created when the
			// base has none.  Replacing wholesale left every key inside it
			// unmarked in setBy, so a later drop-in setting a policy list in
			// there looked unset and overwrote it silently; recursing into an
			// empty map marks them on the way through instead.
			existing, ok := base[key].(map[string]any)
			if !ok {
				existing = map[string]any{}
				base[key] = existing
			}
			if err := mergeInto(existing, sub, full, source, setBy); err != nil {
				return err
			}
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
	sections   = []string{"server", "keeper", "executor", "exec", "ssh", "secrets", "audit"}
	serverKeys = []string{"socket_path", "socket_mode", "max_concurrency",
		"max_request_bytes", "allowed_groups", "max_redacts_per_min"}
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
	// 1, not 0: an unbuffered channel refuses every request as busy.
	if out.MaxConcurrency, err = atLeast(sec, "max_concurrency", where, out.MaxConcurrency, 1); err != nil {
		return err
	}
	if out.MaxRequestBytes, err = atLeast(sec, "max_request_bytes", where, out.MaxRequestBytes, 1); err != nil {
		return err
	}
	if out.AllowedGroups, err = stringList(sec["allowed_groups"], where, out.AllowedGroups); err != nil {
		return err
	}
	// Zero means no limit.
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
	// Every request is clamped to max_timeout_sec, so a smaller one here would
	// replace default_timeout_sec rather than cap it.
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
	// Each entry is a glob pattern; a malformed one matches nothing at every
	// later stage, reading as a missing store.  Matching the empty string
	// touches no filesystem and reports only ErrBadPattern.
	for _, pattern := range out.Files {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return errf("%s: files entry %q is not a valid glob pattern: %v",
				where, pattern, err)
		}
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
