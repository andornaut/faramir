package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

// diagnoseGroup lists members of the two granting groups that this install does
// not account for. Reported rather than removed: whose grant that is, is not
// this command's to decide.
//
// Both groups, because both survive a re-run that renames what they are for:
// changing --client-group leaves the old group intact with every member, and a
// new --keeper-user leaves the retired account in the group owning the
// ciphertext.
func diagnoseGroup(report *Report, opts Options) {
	// A list so the bail-out below can say how many went unasked.
	type granting struct{ label, name, grants string }
	groups := []granting{
		{"client group", opts.ClientGroup,
			"reach the broker socket, and enter a tree enrolled with it"},
	}
	// Only where the secrets group is not the client group, which is already
	// listed.
	if opts.SecretsGroup != "" && opts.SecretsGroup != opts.ClientGroup {
		groups = append(groups, granting{"secrets group", opts.SecretsGroup,
			"read and replace the ciphertext in the secrets directory"})
	}
	// The operator is a member of the client group by construction, so without
	// their name the account this install admitted cannot be told from one left
	// behind, and the remedy printed would be the one change that shuts the agent
	// out of the broker socket.
	if opts.AgentUser == "" {
		report.unaskedf("client group", len(groups), "the agent account is not "+
			"named, so a member of %s cannot be told from an account left behind. Run "+
			"doctor through sudo (SUDO_USER names the account), or record it with "+
			"`sudo faramir init --agent-user`", opts.ClientGroup)
		return
	}
	// The agent's account belongs in the client group and nowhere near the
	// secrets group: membership there is read on the ciphertext, which is the one
	// grant this install exists to keep from it. Calling it expected in both left
	// one line saying "no unexpected members" beside another failing over that
	// exact member.
	service := []string{opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	for _, group := range groups {
		known := service
		if group.name == opts.ClientGroup {
			known = append(append([]string{}, service...), opts.AgentUser)
		}
		diagnoseGroupOutsiders(report, group.label, group.name, known, group.grants)
	}
}

// diagnoseGroupOutsiders is one group's membership against the accounts this
// install uses. Primary membership as well as supplementary: /etc/group lists
// only the second, and a renamed --keeper-user leaves an account holding the
// secrets group as its primary, which is the case worth reporting.
func diagnoseGroupOutsiders(report *Report, label, name string, known []string, grants string) {
	gid, members, err := groupEntry(name)
	if err != nil {
		report.addf(label, StatusFailed, "no group %q, so nothing can %s", name, grants)
		return
	}
	primary, err := primaryMembers(gid)
	if err != nil {
		report.addf(label, StatusFailed, "could not read which accounts have %s "+
			"as their primary group (%v), so who can %s went unverified", name, err, grants)
		return
	}
	var outsiders []string
	for _, member := range append(members, primary...) {
		if member != "" && !slices.Contains(known, member) &&
			!slices.Contains(outsiders, member) {
			outsiders = append(outsiders, member)
		}
	}
	if len(outsiders) == 0 {
		report.addf(label, StatusOK, "%s has no unexpected members", name)
		return
	}
	report.addf(label, StatusWarn, "%s has members this install does not use: "+
		"%s. Membership lets them %s. Drop one with: gpasswd -d <account> %s, or "+
		"usermod -g <other> <account> where it is the primary group",
		name, strings.Join(outsiders, ", "), grants, name)
}

// passwdFile is where the accounts are. A variable so a test can point at one
// it wrote.
var passwdFile = "/etc/passwd"

// primaryMembers is the accounts whose primary gid is this group, which
// /etc/group does not record.
func primaryMembers(gid string) ([]string, error) {
	body, err := os.ReadFile(passwdFile)
	if err != nil {
		return nil, err
	}
	var accounts []string
	for line := range strings.Lines(string(body)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && fields[3] == gid {
			accounts = append(accounts, fields[0])
		}
	}
	return accounts, nil
}

// groupFile is where the groups are. A variable so a test can point at one it
// wrote.
var groupFile = "/etc/group"

// groupEntry is a group's gid and its supplementary members, read from the same
// line so both describe one entry. The gid is what the primary members are
// found by.
func groupEntry(name string) (gid string, members []string, err error) {
	body, readErr := os.ReadFile(groupFile)
	if readErr != nil {
		return "", nil, readErr
	}
	for line := range strings.Lines(string(body)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		if fields[3] == "" {
			return fields[2], nil, nil
		}
		return fields[2], strings.Split(fields[3], ","), nil
	}
	return "", nil, fmt.Errorf("no group %q in %s", name, groupFile)
}

// resolveIdentities finds the accounts and groups this install actually uses,
// rather than the ones a default would name: every check below asks what a
// named account can reach, so a wrong name answers confidently about an account
// this host may not have.
//
// The unit is the source of truth for a service account, being what systemd
// reads; the config for the client group, being what the broker checks; and the
// secrets directory's own group for the secrets group, being what the modes are
// set to. A flag still wins, for a host whose install is not this machine's.
//
// Failing rather than falling back: each of these is readable on any working
// install.
func resolveIdentities(report *Report, opts Options, cfg *config.Config) (Options, bool) {
	for _, role := range []struct {
		unit string
		into *string
		flag string
	}{
		{hostunit.BrokerUnit, &opts.BrokerUser, hostlayout.BrokerUserFlag},
		{hostunit.KeeperUnit, &opts.KeeperUser, hostlayout.KeeperUserFlag},
		{hostunit.ExecUnit, &opts.ExecUser, hostlayout.ExecUserFlag},
	} {
		if *role.into != "" {
			continue
		}
		account, err := hostunit.User(role.unit)
		if err != nil {
			report.addf("identities", StatusFailed, "cannot tell which account "+
				"runs %s (%v), so the checks below have no account to ask about. Reinstall, "+
				"or pass %s", role.unit, err, role.flag)
			return opts, false
		}
		*role.into = account
	}

	if opts.ClientGroup == "" {
		if cfg.Server.AllowedGroup == "" {
			report.addf("identities", StatusFailed, "[server] allowed_group is unset, so "+
				"the broker admits nobody but root and itself. Run `sudo faramir init "+
				"--client-group NAME`, or pass --client-group to examine anyway")
			return opts, false
		}
		opts.ClientGroup = cfg.Server.AllowedGroup
	}
	if opts.SecretsGroup == "" {
		dir := filepath.Join(opts.ConfigDir, "secrets")
		group, err := asaccount.GroupOf(dir)
		if err != nil {
			report.addf("identities", StatusFailed, "cannot read the group "+
				"owning %s (%v). That group keeps every account but the keeper out of the "+
				"ciphertext. Reinstall, or pass --secrets-group", dir, err)
			return opts, false
		}
		opts.SecretsGroup = group
	}

	report.addf("identities", StatusOK, "%s, %s, %s, in %s, secrets owned by %s",
		opts.BrokerUser, opts.KeeperUser, opts.ExecUser, opts.ClientGroup, opts.SecretsGroup)
	return opts, true
}
