// Package config loads /etc/faramir/config.toml. There is no command
// allowlist: the broker runs what it is asked to, as a uid that holds nothing,
// and redacts the output.
//
// Decoded into a raw map and hand-validated rather than unmarshalled into
// structs, so a mistyped key is named rather than ignored.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	DefaultConfigPath = "/etc/faramir/config.toml"
	defaultPATH       = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// sopsExecPATH is the PATH sops runs under, wherever the install runs it. Fixed and absolute, not inherited: which sops decrypts the store
	// must not depend on how the keeper unit was launched, and the account that
	// resolves a bare "sops" here is the one holding the age key. Equal to
	// defaultPATH today but a separate concern, so a change to the brokered
	// command's PATH cannot move sops resolution with it.
	sopsExecPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// The one key three sections share, named once so the list of keys a section
	// accepts and the lookup that reads it cannot drift apart.
	keySocketPath = "socket_path"
	// keyPath is the TOML key both entry kinds spell a file with.
	keyPath = "path"
	// keyCommand is the TOML key a [[secret.block]] entry names a command with,
	// and the section name [command] happens to be the same word.
	keyCommand = "command"
	// keyStrict is the TOML key both entry kinds tighten a rule with.
	keyStrict = "strict"
	// keyAllowedUser is the key the two internal sockets name their one client
	// with, and keyKey is [ssh] key as well as the selector a link reads with.
	keyAllowedUser = "allowed_user"
	keyKey         = "key"
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
	// MaxStdinBytes is the most a caller may pipe into a brokered command. The
	// bytes travel inside the request, base64 encoded, so this has to leave room
	// under MaxRequestBytes for the command, the cwd and the refs beside them:
	// 128 KiB encodes to about 171 KB of a 256 KB line. More than that is
	// refused rather than truncated, a command that read half its input having
	// done something nobody asked for.
	MaxStdinBytes = 128 << 10
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
	// MinRefreshSec is the soonest the broker will ask the keeper again whether a
	// managed file changed. Checked when a command arrives rather than on a
	// timer, so an idle host makes no round trip.
	//
	// Never a config key, having only one sensible value: the question is a stat
	// per managed file and costs about 0.04 ms on a command that already costs
	// two milliseconds, so a larger one saves nothing measurable. What it would
	// spend is real -- this is how long a value rotated outside faramir stays
	// outside the redactor, and that window opens exactly when an operator has
	// just rotated a value and runs a command to see that it took. Every value
	// above this one is worse in the only direction that leaks.
	//
	// It does not bound the linked files: the broker stats those on every
	// request, so a credential another tool has just rotated is in the redactor
	// at once.
	MinRefreshSec = 1
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
	return SecretConfig{DecryptCommand: DecryptCommand(), MinLength: 8}
}

// DefaultSudoTimeoutSec is how long a question waits for a human.
const DefaultSudoTimeoutSec = 120

// DecryptCommand is how the keeper invokes sops. Never a config key: the
// account this runs as is the one holding the age key.
func DecryptCommand() []string {
	return []string{"sops", "--output-type", "json", "--decrypt", "{file}"}
}

// SopsEnv is the environment every sops the install runs is started with:
// the keeper decrypting the store, `faramir secrets` editing it, and the
// rule-coverage check. Fixed rather than inherited, so nothing about the
// calling process reaches sops, with one exception: HOME is passed through,
// falling back to /tmp, because sops writes its keys directory under it. What
// a caller adds is only the age key file it holds.
func SopsEnv() []string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	return []string{"PATH=" + sopsExecPATH, "HOME=" + home, "LANG=C.UTF-8"}
}

// secretPatterns is the managed store, derived from where the config sits
// rather than configured, so it cannot be pointed at a checkout that a clone or
// a branch could move. One extension, not the three sops can read: faramir
// writes the store, and a second spelling would be a second way for a file to
// be named.
func secretPatterns(configPath string) []string {
	dir := filepath.Join(filepath.Dir(configPath), "secrets")
	return []string{filepath.Join(dir, "*.sops.yml")}
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
