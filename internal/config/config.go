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
	return errf("%s: unknown key(s): %s; known keys: %s",
		where, strings.Join(unknown, ", "), strings.Join(sorted, ", "))
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
	case bool:
		return 0, errf("%s: expected an octal string or integer", where)
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

func boolean(value any, where string, fallback bool) (bool, error) {
	if value == nil {
		return fallback, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, errf("%s: expected a boolean, got %T", where, value)
	}
	return b, nil
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
}

type ExecConfig struct {
	// No default: where commands run is a property of the deployment, and a
	// broker that guesses would run them somewhere the operator never named.
	DefaultCwd        string
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
type KeeperConfig struct {
	SocketPath       string
	SocketMode       os.FileMode
	AllowedUsers     []string
	AllowedGroups    []string
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
	AllowedGroups  []string
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

type AuditConfig struct {
	RawLog         string
	MaxRecordBytes int
}

type Config struct {
	Path     string
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
	return FromMap(raw, path)
}

var (
	serverKeys = []string{"socket_path", "socket_mode", "max_concurrency",
		"max_request_bytes", "allowed_uids", "allowed_groups"}
	keeperKeys = []string{"socket_path", "socket_mode", "allowed_users",
		"allowed_groups", "age_key_credential", "age_key_file"}
	executorKeys = []string{"socket_path", "socket_mode", "allowed_users",
		"allowed_groups", "max_concurrency"}
	execKeys = []string{"default_cwd", "default_timeout_sec", "max_timeout_sec",
		"max_output_bytes", "base_env", "term_cols", "term_rows", "kill_grace_sec"}
	sshKeys = []string{"keys", "agent_socket", "agent_socket_mode", "exec_group",
		"ssh_agent", "ssh_add"}
	secretsKeys = []string{"files", "decrypt_command", "refresh_interval_sec",
		"min_length", "min_unique_chars", "min_entropy_bits_per_char"}
	auditKeys = []string{"raw_log", "max_record_bytes"}
)

func FromMap(raw map[string]any, path string) (*Config, error) {
	cfg := &Config{Path: path}

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
	if _, ok := raw["sync"]; ok {
		// Ignoring the section would leave a config that reads as though the
		// broker still executed a separate checkout, and an [exec] default_cwd
		// still pointing at a directory nothing populates.
		return nil, errf("%s: [sync] no longer exists. Brokered commands run in "+
			"the agent's working tree directly, so there is nothing to promote: "+
			"delete the section and point [exec] default_cwd and [secrets] files "+
			"at that tree.", path)
	}

	if _, ok := raw["allow"]; ok {
		// Ignoring the rules would leave a config that reads as though commands
		// were still being constrained by it.
		return nil, errf("%s: [[allow]] no longer exists. The broker runs what it "+
			"is asked to run, as a uid that holds nothing, and redacts the "+
			"output; a rule permitting any interpreter reached past every "+
			"constraint these expressed. Delete the [[allow]] tables.", path)
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
		AllowedGroups: []string{"devwork"},
	}
	if out.SocketPath, err = str(sec["socket_path"], where, out.SocketPath); err != nil {
		return err
	}
	if v, ok := sec["socket_mode"]; ok {
		if out.SocketMode, err = octalMode(v, fmt.Sprintf("%s: server.socket_mode", path)); err != nil {
			return err
		}
	}
	if out.MaxConcurrency, err = integer(sec["max_concurrency"], where, out.MaxConcurrency); err != nil {
		return err
	}
	if out.MaxRequestBytes, err = integer(sec["max_request_bytes"], where, out.MaxRequestBytes); err != nil {
		return err
	}
	if out.AllowedUIDs, err = intList(sec["allowed_uids"], where, nil); err != nil {
		return err
	}
	if out.AllowedGroups, err = stringList(sec["allowed_groups"], where, out.AllowedGroups); err != nil {
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
	if out.AllowedGroups, err = stringList(sec["allowed_groups"], where, nil); err != nil {
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
	if out.AllowedGroups, err = stringList(sec["allowed_groups"], where, nil); err != nil {
		return err
	}
	if out.MaxConcurrency, err = integer(sec["max_concurrency"], where, out.MaxConcurrency); err != nil {
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
	if _, ok := sec["allowed_bin_dirs"]; ok {
		// It went with the allowlist: it bounded argv[0] only, so any rule
		// permitting bash or python walked straight past it, and what it
		// reliably did instead was refuse every pipx, venv, shim and /opt
		// install on the host.
		return errf("%s: [exec] allowed_bin_dirs no longer exists. A bare command "+
			"name is looked up on [exec.base_env] PATH, which is the PATH the "+
			"child gets; put a venv or shim directory there.", path)
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
	if out.DefaultCwd, err = str(sec["default_cwd"], where, ""); err != nil {
		return err
	}
	if out.DefaultTimeoutSec, err = integer(sec["default_timeout_sec"], where, out.DefaultTimeoutSec); err != nil {
		return err
	}
	if out.MaxTimeoutSec, err = integer(sec["max_timeout_sec"], where, out.MaxTimeoutSec); err != nil {
		return err
	}
	if out.MaxOutputBytes, err = integer(sec["max_output_bytes"], where, out.MaxOutputBytes); err != nil {
		return err
	}
	if out.BaseEnv, err = stringMap(sec["base_env"], where, out.BaseEnv); err != nil {
		return err
	}
	if out.TermCols, err = integer(sec["term_cols"], where, out.TermCols); err != nil {
		return err
	}
	if out.TermRows, err = integer(sec["term_rows"], where, out.TermRows); err != nil {
		return err
	}
	if out.KillGraceSec, err = integer(sec["kill_grace_sec"], where, out.KillGraceSec); err != nil {
		return err
	}
	if out.DefaultCwd == "" {
		return errf("%s: [exec] default_cwd is required; name the directory "+
			"brokered commands run in (see etc/config.toml)", path)
	}
	return nil
}

func loadSecrets(raw map[string]any, path string, out *SecretsConfig) error {
	where := fmt.Sprintf("%s: [secrets]", path)
	sec, err := table(raw, "secrets", path)
	if err != nil {
		return err
	}
	var moved []string
	for _, k := range []string{"age_key_credential", "age_key_file"} {
		if _, ok := sec[k]; ok {
			moved = append(moved, k)
		}
	}
	if len(moved) > 0 {
		sort.Strings(moved)
		return errf("%s: [secrets] %s moved to [keeper]; the broker no longer "+
			"reads the age key at all", path, strings.Join(moved, ", "))
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
	if out.DecryptCommand, err = stringList(sec["decrypt_command"], where, out.DecryptCommand); err != nil {
		return err
	}
	if out.RefreshIntervalSec, err = integer(sec["refresh_interval_sec"], where, out.RefreshIntervalSec); err != nil {
		return err
	}
	if out.MinLength, err = integer(sec["min_length"], where, out.MinLength); err != nil {
		return err
	}
	if out.MinUniqueChars, err = integer(sec["min_unique_chars"], where, out.MinUniqueChars); err != nil {
		return err
	}
	if out.MinEntropyBitsPerChar, err = float(sec["min_entropy_bits_per_char"], where, out.MinEntropyBitsPerChar); err != nil {
		return err
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
	*out = AuditConfig{RawLog: "/var/log/faramir/raw.log", MaxRecordBytes: 4194304}
	if out.RawLog, err = str(sec["raw_log"], where, out.RawLog); err != nil {
		return err
	}
	if out.MaxRecordBytes, err = integer(sec["max_record_bytes"], where, out.MaxRecordBytes); err != nil {
		return err
	}
	return nil
}
