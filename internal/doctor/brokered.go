package doctor

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/runcmd"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// diagnoseBrokered asks the broker to run something: the one place the answer
// is what a brokered command actually gets. As the operator, the broker
// checking the peer's credentials and root not being in the shared group.
func diagnoseBrokered(report *Report, opts Options, cfg *config.Config, serves brokerServes) {
	// Three states where the command is not sent, each reported as unasked: a
	// broker that refuses it, one whose value set --check did not establish, and
	// one that is not running. Sent anyway, a refusal or an outage would come
	// back as a boundary that does not hold.
	switch serves {
	case servesNothing:
		report.unaskedf("brokered command", 1, "not asked: a managed file did "+
			"not load, so the broker would refuse the command")
		return
	case servesUnknown:
		report.unaskedf("brokered command", 1, "not asked: --check did not "+
			"report, so whether the broker would refuse the command is unknown")
		return
	case servesValues:
		// The command is sent, which is the rest of this function.
	}
	if opts.BrokerVersion == "" {
		report.unaskedf("brokered command", 1, "not asked: the broker did not "+
			"answer, so the command could not be sent")
		return
	}
	faramir := filepath.Join(hostlayout.DefaultBinDir, "faramir")
	brokered := func(args ...string) (string, error) {
		return asaccount.Output(opts.AgentUser, append([]string{faramir, "run", "--quiet", "--"}, args...)...)
	}
	out, err := brokered("id", "-un")
	if err != nil {
		// Not a broken install: doctor is itself inside a brokered command, and
		// the check it wants to make is the one thing that cannot run there.
		if why := protocol.NestedRun(); why != "" {
			report.unaskedf("brokered command", 1, "not asked: %s", why)
			return
		}
		report.addf("brokered command", StatusFailed, "%s could not run one: %v",
			opts.AgentUser, err)
		return
	}
	if got := strings.TrimSpace(out); got != opts.ExecUser {
		report.addf("brokered command", StatusFailed, "runs as %s, expected %s: it is "+
			"holding whatever that account can reach", got, opts.ExecUser)
		return
	}
	// The key arrives through LoadCredential=, so the credential directory and
	// the environment are where a child might find it. Both go through a shell,
	// being a glob and an expansion, and -c alone: -l would source the
	// executor's login profiles on every run and let a banner into the verdict.
	//
	// Each script answers with a word of its own, so the verdict reads the same
	// under any locale, and nothing a probe might find is printed or carried:
	// the environment probe never expands the value and the credential probe
	// sends the read to /dev/null, so a hit reaches neither this output nor the
	// audit record.
	leaks := []struct{ name, script string }{
		{"the environment", `[ -z "${SOPS_AGE_KEY:-}" ] && echo clean || echo readable`},
		{"a systemd credential", `cat /run/credentials/*/age_key >/dev/null 2>&1 && echo readable || echo clean`},
	}
	for _, leak := range leaks {
		out, err := brokered("bash", "-c", leak.script)
		got := strings.TrimSpace(out)
		switch {
		case err != nil:
			// A probe that did not run answered nothing: scoring it clean would
			// pass the boundary on a broken probe, and scoring it a leak would
			// fail a healthy host over one.
			report.unaskedf("brokered command", 1, "the %s probe could not run "+
				"(%v), so whether the age key reaches a child there was not checked",
				leak.name, err)
			return
		case got == "readable":
			report.addf("brokered command", StatusFailed, "the age key reaches a child "+
				"through %s; inspect it by hand", leak.name)
			return
		case got != "clean":
			report.unaskedf("brokered command", 1, "the %s probe answered something "+
				"other than its own verdict, so it was not read", leak.name)
			return
		}
	}
	report.addf("brokered command", StatusOK, "runs as %s, and the age key reaches it "+
		"through neither the environment nor a credential", opts.ExecUser)
	diagnoseRedaction(report, opts, cfg)
}

// diagnoseRedaction is the end-to-end claim, made with a value of its own: a
// synthetic secret is sealed into the store, refreshed in, injected into a
// real command and expected back as exactly its token, then removed and
// refreshed out. A dedicated value rather than one of the operator's, so a
// host whose redaction is broken leaks a random string into its own audit log
// and nothing else.
func diagnoseRedaction(report *Report, opts Options, cfg *config.Config) {
	const name = "redaction"
	if cfg == nil {
		report.unaskedf(name, 1, "the config did not load, so no probe value was sealed")
		return
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		report.unaskedf(name, 1, "sops is not on this PATH, so no probe value "+
			"could be sealed and redaction was not exercised")
		return
	}
	target := filepath.Join(opts.ConfigDir, "secrets", "doctor-probe.sops.yml")
	if hostfs.Exists(target) {
		report.unaskedf(name, 1, "%s already exists, so no probe was written over it", target)
		return
	}
	value := make([]byte, 16)
	if _, err := cryptorand.Read(value); err != nil {
		report.unaskedf(name, 1, "no randomness for a probe value: %v", err)
		return
	}
	plainDir, err := os.MkdirTemp("", "faramir-doctor")
	if err != nil {
		report.unaskedf(name, 1, "no directory for the probe's plaintext: %v", err)
		return
	}
	defer func() { _ = os.RemoveAll(plainDir) }()
	plain := filepath.Join(plainDir, "probe.yml")
	body := "doctor:\n  probe: " + hex.EncodeToString(value) + "\n"
	if err := os.WriteFile(plain, []byte(body), 0o600); err != nil {
		report.unaskedf(name, 1, "could not write the probe's plaintext: %v", err)
		return
	}
	sealed, err := runcmd.OutputWithin(time.Minute, sops,
		"--config", filepath.Join(opts.ConfigDir, ".sops.yaml"),
		"--encrypt", "--filename-override", target, plain)
	if err != nil {
		report.unaskedf(name, 1, "could not seal a probe value (%v), so "+
			"redaction was not exercised. The `sops config` and `rule coverage` checks "+
			"say why", err)
		return
	}
	// 0640 into the setgid store, which hands the keeper's group over, exactly
	// as a managed file is written.
	if err := os.WriteFile(target, []byte(sealed), 0o640); err != nil { //nolint:gosec // G306: the store's own mode; the file is ciphertext and the keeper's group must read it
		report.unaskedf(name, 1, "could not write the probe into the store: %v", err)
		return
	}
	// Removed and refreshed out whatever happens below, so the probe never
	// outlives the examination.
	defer func() {
		_ = os.Remove(target)
		_ = refreshStore(cfg.Server.SocketPath)
	}()
	if why := refreshStore(cfg.Server.SocketPath); why != "" {
		report.unaskedf(name, 1, "the broker did not take the probe value: %s", why)
		return
	}
	faramir := filepath.Join(hostlayout.DefaultBinDir, "faramir")
	probe, err := asOperator(opts, faramir, "run", "--quiet",
		"--env", "FARAMIR_DOCTOR_PROBE=faramir://doctor/probe", "--",
		"printenv", "FARAMIR_DOCTOR_PROBE")
	if err != nil {
		report.addf(name, StatusFailed, "could not run the probe: %v", err)
		return
	}
	// The whole output has to be the probe's own token: a substring match
	// would pass a value redacted in part.
	if strings.TrimSpace(probe) != redact.TokenFor("doctor/probe") {
		report.addf(name, StatusFailed, "a command that printed the sealed "+
			"probe value did not return its token, so injected values reach output "+
			"unredacted. The probe value was synthetic and has been removed")
		return
	}
	report.addf(name, StatusOK, "a sealed probe value came back as its token")
}

// refreshStore asks the running broker to re-read the managed store, the same
// op `faramir vault` sends, and returns why it did not, empty on success.
func refreshStore(socketPath string) string {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return fmt.Sprintf("the broker could not be reached at %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	if err := sockutil.Send(conn, map[string]any{
		"op": "refresh", "version": version.Version}); err != nil {
		return fmt.Sprintf("the refresh could not be sent: %v", err)
	}
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil || len(line) == 0 {
		return "the broker did not answer the refresh"
	}
	var response struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return "the refresh answer was not readable"
	}
	if response.Error != nil {
		return response.Error.Message
	}
	return ""
}
