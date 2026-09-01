package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	osexec "os/exec"
	"os/user"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/escalation"
)

// CheckOutput is the operator-facing --check report: the refs refused at load,
// which the agent-facing status op never names, and the state of the configured
// SSH keys. Both exit non-zero, being a broker that serves without doing the
// job it was installed for.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	sshInfo, problems := s.describeSSH()
	escalationInfo, escalationProblems := s.describeEscalation()
	policy := s.policyProblems()
	body, err := json.MarshalIndent(map[string]any{
		"config":  s.Config.Path,
		"secrets": secrets, "ssh": sshInfo, "sudo": escalationInfo, "policy": policy,
	}, "", "  ")
	if err != nil {
		// Non-zero: a report that cannot be rendered is a broker nobody can
		// check.
		return []byte("the --check report could not be rendered: " + err.Error() + "\n"), 1
	}

	code := 0
	if len(policy) > 0 {
		for _, problem := range policy {
			log.Printf("socket policy: %s", problem)
		}
		code = 1
	}
	// A link that did not load: one ref refused, the broker still serving. Not
	// logged for the reason below, and non-zero so `doctor` and a converge run
	// see it rather than waiting for a command to ask for the ref.
	if degraded, _ := secrets["degraded_links"].(map[string]string); len(degraded) > 0 {
		code = 1
	}
	refused, _ := secrets["not_redactable"].(map[string]string)
	if len(refused) > 0 {
		// Nothing logged: loading already named every refused secret, and the JSON
		// body carries the same set as not_redactable.
		code = 1
	}
	// Reported and not counted. The daemon serves an empty value set, there
	// being no value for output to carry that the redactor lacks, so an operator
	// asking whether the host serves anything is told and a converge run is not
	// failed over a host that manages no credentials. What does fail is a
	// managed file that was found and did not load, below.
	if s.Store.Count() == 0 {
		log.Printf("the broker holds no managed values, so nothing is injectable " +
			"and nothing is redacted. Commands still run: there is nothing to " +
			"cover. A store on a filesystem that is not mounted looks the same " +
			"from here, so check that this host is meant to manage none")
	}
	if absent := s.Store.UnresolvedPatterns(); len(absent) > 0 {
		log.Printf("%d configured entry(ies) named no file: %v", len(absent), absent)
	}
	// A ref two managed files define differently. The loser is on disk and in no
	// redactor, so a command that prints it prints it in the clear: the same
	// consequence as a ref too short to cover, and counted the same way.
	if shadowed := s.Store.ShadowedRefs(); len(shadowed) > 0 {
		log.Printf("%d ref(s) are defined with different values by more than one "+
			"managed file; one value wins and the other is in no redactor: %v",
			len(shadowed), shadowed)
		code = 1
	}
	// Every value the broker failed to load is one it cannot redact.
	if fatal := s.Store.LoadErrors(); len(fatal) > 0 {
		log.Printf("%d secret load failure(s): %v", len(fatal), fatal)
		log.Printf("those values are absent from the redactor, so a command " +
			"that prints one prints it in plaintext")
		code = 1
	}
	if len(problems) > 0 {
		log.Printf("the broker cannot use the configured SSH key: %v", problems)
		log.Printf("brokered commands will reach no host that expects it; " +
			"place the key, or leave [ssh] key unset to authenticate some other way")
		code = 1
	}
	// Same weighting as the SSH key: an escalation that cannot be asked for
	// breaks only the commands that sudo, and those fail at the point of use with
	// sudo's own error.
	if len(escalationProblems) > 0 {
		log.Printf("this host cannot answer an escalation: %v", escalationProblems)
		log.Printf("a brokered command that runs sudo will fail to authenticate; " +
			"re-run `faramir init --allow-sudo`, or re-run without it to take the grant " +
			"away entirely")
		code = 1
	}
	// Not a warning: a host whose audit log cannot be written runs no brokered
	// command at all.
	if reason := s.Audit.Unwritable(); reason != "" {
		log.Printf("the audit log cannot be written: %s", reason)
		log.Printf("every brokered command is refused while that holds, a command " +
			"that cannot be recorded not being one this host runs")
		code = 1
	}
	return body, code
}

// describeEscalation reports whether this host could answer an escalation, and
// why not when it could not. Files rather than a live probe: putting the
// question would mean waiting on a human, and `--check` runs from `init`.
func (s *Server) describeEscalation() (map[string]any, []string) {
	info := map[string]any{"enabled": s.Escalation.Enabled()}
	if !s.Escalation.Enabled() {
		// The install that granted no sudoers entry, which is the default one.
		return info, nil
	}
	cfg := s.Config.Sudo
	info["exec_user"] = cfg.ExecUser
	info["pam_service"] = cfg.PamService
	info["helper"] = cfg.Helper
	info["notify_command"] = cfg.NotifyCommand

	var problems []string
	// The helper is what sudo's PAM service execs, as root. Absent, every
	// escalation fails closed.
	if _, err := os.Stat(cfg.Helper); err != nil {
		problems = append(problems, cfg.Helper+": "+err.Error()+
			" (the PAM service execs it, so no escalation can be approved)")
	}
	// The stack that execs it, wherever it is on this host: a service file of
	// faramir's own where sudo can be sent to one by name, and a block in the
	// stacks every account reads where it cannot. Absent either way, PAM falls
	// back to /etc/pam.d/other, which asks for a password nothing supplies on a
	// normal host and authenticates anything on one whose `other` is permissive;
	// doctor checks that too.
	if stack, err := escalation.Stack(escalation.PamDir, cfg.PamStack, cfg.PamService); err != nil {
		problems = append(problems, "nothing here authenticates an escalation: "+
			err.Error()+" (sudo would fall back to /etc/pam.d/other for "+
			cfg.ExecUser+")")
	} else {
		info["pam_stack"] = stack
	}
	// The notifier is optional, `faramir sudo watch` being where a
	// question is seen, but one configured and absent announces nothing,
	// silently.
	if len(cfg.NotifyCommand) > 0 {
		if _, err := osexec.LookPath(cfg.NotifyCommand[0]); err != nil {
			problems = append(problems, cfg.NotifyCommand[0]+": "+err.Error()+
				" ([sudo] notify_command names it, so nothing announces a pending request)")
		}
	}
	return info, problems
}

// policyProblems names the settings that widen what a socket admits. The
// keeper's socket is the age key by another route, and the executor's runs a
// command with no policy, redaction or audit record; each has exactly one
// legitimate client, this process. Identity by uid rather than name, the
// accounts being renamable at install time.
func (s *Server) policyProblems() []string {
	problems := []string{}
	// The socket itself, not a config key describing it: under systemd the
	// .socket unit's SocketMode= is what the mode ends up as. Unbound means
	// unchecked rather than passing.
	path := s.Config.Server.SocketPath
	if info, err := os.Stat(path); err != nil {
		log.Printf("%s is not bound, so its mode went unchecked: %v", path, err)
	} else if mode := info.Mode().Perm(); mode&0o007 != 0 {
		problems = append(problems, fmt.Sprintf(
			"%s is %04o: every account on this host can reach the broker, whatever "+
				"allowed_group says", path, mode))
	}
	if os.Geteuid() == 0 {
		log.Printf("running as root, so [keeper] and [executor] allowed_user were " +
			"not checked: run --check as the broker's own account")
		return problems
	}
	for _, socket := range []struct {
		section string
		account string
		cost    string
	}{
		{"keeper", s.Config.Keeper.AllowedUser,
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor", s.Config.Executor.AllowedUser,
			"a command sent there runs unredacted and unlogged"},
	} {
		// Unset is not checked: it fails loudly on its own, and what is looked for
		// here is a name admitting the wrong account.
		if socket.account != "" && !isSelf(socket.account) {
			problems = append(problems, fmt.Sprintf(
				"[%s] allowed_user names %s, which is not the broker: %s",
				socket.section, socket.account, socket.cost))
		}
	}
	return problems
}

// isSelf reports whether name resolves to the uid this process runs as.
func isSelf(name string) bool {
	entry, err := user.Lookup(name)
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(entry.Uid)
	return err == nil && uid == os.Geteuid()
}

// unusableReason names why ssh-add will refuse this key, or "" if it will take
// it: a passphrase-protected key, or [ssh] key pointing at the .pub. Either
// leaves the broker up with an agent holding nothing. The parse is what ssh-add
// would do, and its error carries no key material.
func unusableReason(data []byte) string {
	_, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		return ""
	}
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		return "passphrase-protected; the broker has no way to type one, " +
			"so ssh-add will refuse it"
	}
	if _, _, _, _, pubErr := ssh.ParseAuthorizedKey(data); pubErr == nil {
		return "this is a public key; [ssh] key must name the private key"
	}
	return "not a usable private key"
}

// describeSSH reports whether the broker can read and use the configured key,
// and why not when it cannot. A file check rather than a loaded-key count:
// --check runs before Ssh.Start, and starting a second agent would replace a
// running broker's socket.
func (s *Server) describeSSH() (map[string]any, []string) {
	info := map[string]any{"agent_socket": s.Config.Ssh.AgentSocket}
	path := s.Config.Ssh.Key
	// Absent is deliberate: the key then lives where the executor can read it.
	if path == "" {
		return info, nil
	}

	key := map[string]any{"path": path}
	info["key"] = key
	data, err := os.ReadFile(path)
	if err != nil {
		key["readable"] = false
		return info, []string{path + ": " + err.Error()}
	}
	key["readable"] = true
	if reason := unusableReason(data); reason != "" {
		key["usable"] = false
		key["reason"] = reason
		return info, []string{path + ": " + reason}
	}
	key["usable"] = true
	return info, nil
}
