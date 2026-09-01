package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// brokerUnit records the config the daemons loaded. A variable so a test can
// point it at a fixture, and taken from install rather than written out again:
// init refuses a config move against the same file.
var brokerUnit = hostunit.Path("faramir-broker.service")

// status is what a running broker says about itself: where its config is, and
// which build is answering.
type status struct {
	configDir string
	version   string
	// build is which build of that version, for the versions that do not name
	// one. Empty from a release, and from a broker of a build that predates it.
	build string
}

// askBroker asks a running broker about itself in one round trip, and returns a
// zero status on any failure, every caller having something to fall back on.
func askBroker(socketPath string) status {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return status{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := sockutil.Send(conn, map[string]any{
		"op": opStatus, "version": version.Version}); err != nil {
		return status{}
	}
	// The write half stays open. The broker reads this connection for the whole
	// of a run and takes an EOF as the caller having gone, killing the command;
	// nothing on this socket half-closes, so there is no per-op rule to get
	// wrong when an op becomes a long one.
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return status{}
	}
	// The status body is itself JSON, carried as the response's output string.
	var response struct {
		Output  string `json:"output"`
		Version string `json:"version"`
		Error   *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return status{}
	}
	// A broker of another release refuses this before it reads the op, so the
	// refusal is the answer: what refused names the build that is running, and
	// there is no status body to read. Reported as skew rather than as a broker
	// that said nothing.
	if response.Error != nil {
		return status{version: response.Version}
	}
	var body struct {
		Config  string `json:"config"`
		Version string `json:"version"`
		Build   string `json:"build"`
	}
	if err := json.Unmarshal([]byte(response.Output), &body); err != nil {
		return status{}
	}
	out := status{version: body.Version, build: body.Build}
	if body.Config != "" {
		out.configDir = filepath.Dir(body.Config)
	}
	return out
}

// unitConfigFile reads the config path out of the broker's unit and its
// drop-ins, or "" when neither is readable or names one: what the broker was
// installed to load, which is the answer left when it is not running. The same
// reader init refuses a config move against.
func unitConfigFile() string {
	return hostunit.ConfigFile(brokerUnit)
}

// configFileFrom is the config.toml a running install loads, given an answer
// already asked for: the broker's own, then the path the broker's unit names.
// The broker answers with the file it loaded, so its directory and that name
// reconstruct it.
//
// Neither answering is an error rather than the compiled-in default. A caller
// cannot be expected to know where the config lives, and the default is a
// guess: acting on the wrong install is worse than saying which install could
// not be found.
func configFileFrom(st status) (string, error) {
	if st.configDir != "" {
		return filepath.Join(st.configDir, "config.toml"), nil
	}
	if path := unitConfigFile(); path != "" {
		return path, nil
	}
	return "", errNoInstall
}

// findConfigFile is configFileFrom with $FARAMIR_CONFIG in front of it, which
// is the whole ladder every command but init climbs. The same variable the
// daemons are given by their units and the one config.Load reads: not a way for
// a caller to name an install it happens to know about, but the way out of the
// case configFileFrom ends in, a host whose broker is down and whose unit is
// gone still having an operator who can say where the config is.
func findConfigFile(st status) (string, error) {
	path := os.Getenv("FARAMIR_CONFIG")
	if path == "" {
		return configFileFrom(st)
	}
	// The file, not the directory it is in. The flag this replaced took a
	// directory, so an operator migrating writes FARAMIR_CONFIG=/etc/faramir by
	// hand, and reading it as a file would make the install /etc: `block add`
	// would then write a new /etc/config.toml, which is the wrong install this
	// whole ladder exists to refuse.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "", fmt.Errorf("FARAMIR_CONFIG=%s is a directory; it names the "+
			"config file, so this wants %s", path, filepath.Join(path, "config.toml"))
	}
	return path, nil
}

// errNoInstall names both places that were asked, so the operator knows which
// one to repair rather than which directory to pass.
var errNoInstall = fmt.Errorf("no install found: the broker did not answer and %s names no config file. Start the "+
	"broker, set FARAMIR_CONFIG, or run `faramir init`", brokerUnit)

// resolveConfigDir is the directory holding this host's config, for the
// commands that act on the install rather than read it.
func resolveConfigDir(socketPath string) (string, error) {
	path, err := findConfigFile(askBroker(socketPath))
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

// installedConfigDir is resolveConfigDir for a command that only reports, which
// has to know the install is there before it says what it holds.
//
// The loaders read an absent config as an install carrying no entries, which is
// what init needs on a host that has none yet. A listing given the same answer
// says "no entries" about a config file that is not there, and a mistyped
// $FARAMIR_CONFIG then reads as a host that declares nothing rather than as the
// wrong install: the one thing the ladder exists to refuse.
func installedConfigDir(socketPath string) (string, error) {
	path, err := findConfigFile(askBroker(socketPath))
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("config not found: %s. This reports on an install and "+
			"found none there; $FARAMIR_CONFIG names the config file of the one to "+
			"report on", path)
	}
	return filepath.Dir(path), nil
}

// initConfigDir is where init provisions to. Unlike every other command this
// one takes a flag and falls back to the compiled-in default: a host with no
// install has no broker to ask and no unit to read, which is the case init is
// for, and it is the one command whose caller does decide where the config
// goes.
//
// configFileFrom rather than findConfigFile, so $FARAMIR_CONFIG is not a step.
// It is a variable an operator exports for a shell and `sudo -E` carries
// through, and a leftover from an earlier command must not be what decides
// where a host is provisioned.
func initConfigDir(explicit, socketPath string) string {
	if explicit != "" {
		return explicit
	}
	if path, err := configFileFrom(askBroker(socketPath)); err == nil {
		return filepath.Dir(path)
	}
	return hostlayout.DefaultConfigDir
}
