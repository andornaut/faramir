// Package sshagent runs an ssh-agent held by the broker, usable by children
// that cannot read its keys.
//
// Brokered commands run as faramir-exec.  The SSH keys that reach managed
// hosts have to be usable from there, and the obvious way to arrange that is
// to put them in that uid's home, at which point every brokered command can
// read them, and a leaked fleet key is permanent in a way a leaked password is
// not.
//
// So the broker keeps the key files under its own uid, loads them into an
// agent it owns, and passes only SSH_AUTH_SOCK to the child.  The child can
// authenticate to managed hosts for as long as the broker is running.  It
// cannot read the keys, and it cannot ptrace the agent, which belongs to
// another uid.
//
// Entirely optional: with no [ssh] keys configured no agent is started and
// nothing is injected, and it is up to the operator to arrange authentication
// (usually by putting the keys in the executor's own home instead).
package sshagent

import (
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

const socketWait = 10 * time.Second

type Agent struct {
	config config.SshConfig
	cmd    *exec.Cmd
	socket string
}

func New(cfg config.SshConfig) *Agent { return &Agent{config: cfg} }

func (a *Agent) Enabled() bool { return len(a.config.Keys) > 0 }

// Env is what to add to a child's environment.  Empty unless the agent runs.
func (a *Agent) Env() map[string]string {
	if a.socket == "" {
		return map[string]string{}
	}
	return map[string]string{"SSH_AUTH_SOCK": a.socket}
}

func (a *Agent) Start() {
	if !a.Enabled() {
		log.Printf("no [ssh] keys configured; not starting an agent")
		return
	}
	path := a.config.AgentSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("cannot prepare %s: %v", path, err)
		return
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Remove(path); err != nil {
			log.Printf("cannot prepare %s: %v", path, err)
			return
		}
	}

	// -D keeps it in the foreground, so it is an ordinary child of this
	// process and dies with it rather than lingering with the keys loaded.
	cmd := exec.Command(a.config.SshAgent, "-D", "-a", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		log.Printf("cannot start %s: %v", a.config.SshAgent, err)
		return
	}
	a.cmd = cmd

	if !a.awaitSocket(path) {
		log.Printf("ssh-agent did not create %s; SSH keys will be unavailable", path)
		a.Stop()
		return
	}

	a.grantExecutorAccess(path)
	a.socket = path
	loaded := 0
	for _, key := range a.config.Keys {
		if a.add(key, path) {
			loaded++
		}
	}
	log.Printf("ssh-agent on %s with %d/%d key(s)", path, loaded, len(a.config.Keys))
	if loaded == 0 {
		log.Printf("no SSH keys loaded; commands needing SSH will fail to authenticate")
	}
}

func (a *Agent) awaitSocket(path string) bool {
	deadline := time.Now().Add(socketWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if a.cmd != nil && a.cmd.ProcessState != nil && a.cmd.ProcessState.Exited() {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// grantExecutorAccess lets the executor's uid connect, and nothing else.
//
// ssh-agent creates its socket 0600.  The chown needs the broker to be a
// member of the target group, which the unit arranges with SupplementaryGroups=.
func (a *Agent) grantExecutorAccess(path string) {
	group := a.config.ExecGroup
	if group == "" {
		return
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		log.Printf("group %s does not exist; the executor cannot use the agent", group)
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		log.Printf("cannot hand %s to group %s (%v); is the broker a member of it?", path, group, err)
		return
	}
	if err := os.Chmod(path, a.config.AgentSocketMode); err != nil {
		log.Printf("cannot set mode on %s: %v", path, err)
	}
}

func (a *Agent) add(key, socketPath string) bool {
	cmd := exec.Command(a.config.SshAdd, key)
	cmd.Env = []string{
		"SSH_AUTH_SOCK=" + socketPath,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + envOr("HOME", "/tmp"),
		// A key with a passphrase must fail immediately rather than block
		// startup waiting for input nobody will ever type.
		"SSH_ASKPASS_REQUIRE=never",
		"DISPLAY=",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ssh-add %s failed: %v: %s", key, err, lastLine(string(out)))
		return false
	}
	return true
}

func (a *Agent) Stop() {
	if a.cmd != nil && a.cmd.Process != nil {
		_ = a.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = a.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = a.cmd.Process.Kill()
		}
	}
	a.cmd = nil
	if a.socket != "" {
		_ = os.Remove(a.socket)
	}
	a.socket = ""
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// lastLine is the most useful part of a failed command's output: the final
// line, which is where ssh-add puts its reason.
func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
