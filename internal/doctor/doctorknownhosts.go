package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/knownhosts"
)

// diagnoseKnownHosts reports what a brokered ssh can verify a host against.
// ssh reads the global file before the account's own, so either holding entries
// is enough and the counts are reported together.
//
// Never a failure: nothing pinned is what a host with no fleet looks like, and
// a host may arrange verification some other way. Reported because the state
// is otherwise silent until a playbook hits it. Needs root, the executor's
// file being inside a 0700 home.
func diagnoseKnownHosts(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil || cfg.Ssh.Key == "" {
		return
	}
	layout := hostlayout.Layout{ExecUser: opts.ExecUser}
	path := layout.ExecKnownHosts()
	if os.Geteuid() != 0 {
		report.unaskedf("known hosts", 1, "not asked: reading %s needs root, "+
			"the executor's home being 0700", path)
		return
	}
	// Counted as root and read as the executor, which are different questions:
	// root's mode bypass reads a file the account that runs the command cannot.
	own, global := 0, 0
	unreadable := []string{}
	for _, file := range []struct {
		path  string
		count *int
	}{{knownhosts.GlobalFile, &global}, {path, &own}} {
		if !hostfs.Exists(file.path) {
			continue
		}
		if !asaccount.CanRead(opts.ExecUser, file.path) {
			unreadable = append(unreadable, file.path)
			continue
		}
		*file.count = knownhosts.Count(file.path)
	}
	// An unreadable file is named rather than failed on: the other may hold the
	// whole fleet.
	ignored := ""
	if len(unreadable) > 0 {
		ignored = fmt.Sprintf(". %s cannot read %s, so nothing in it verifies anything; "+
			"sudo chmod a+r %s", opts.ExecUser, strings.Join(unreadable, " or "),
			strings.Join(unreadable, " "))
	}
	if own+global == 0 {
		report.addf("known hosts", StatusOK, "neither %s nor %s holds a host key the "+
			"executor can read, so a brokered ssh refuses a managed host before the "+
			"broker's key is offered. Pin them with `init --known-hosts`, or write %s, "+
			"which every account reads%s", knownhosts.GlobalFile, path, knownhosts.GlobalFile, ignored)
		return
	}
	report.addf("known hosts", StatusOK, "%d host key(s) a brokered ssh verifies against "+
		"(%d in %s, %d in %s)%s", own+global, global, knownhosts.GlobalFile, own, path, ignored)
}
