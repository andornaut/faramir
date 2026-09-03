package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/asaccount"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
)

// diagnoseLinkedAccess asks the two questions the grant exists to make true:
// the broker can read each linked file, and the executor cannot. Asked as
// those accounts rather than worked out from the mode, which is what catches a
// tool having replaced its own file and taken the group with it.
//
// A file that is not there answers neither, and fails too: the entry names a
// value nothing can produce, whether the credential has left the machine or the
// home holding it is not mounted. Which of the two it is, the operator knows and
// this cannot.
func diagnoseLinkedAccess(report *Report, opts Options, cfg *config.Config) {
	const name = "linked file access"
	if len(cfg.Secret.Links) == 0 {
		report.addf(name, StatusOK, "no [[secret.link]] entries are configured")
		return
	}
	accounts, skipped := opts.askable(opts.BrokerUser, opts.ExecUser)
	if skipped || len(accounts) < 2 {
		report.unaskedf(name, len(cfg.Secret.Links), "the broker and executor "+
			"accounts are not both named, so whether the %d linked file(s) are "+
			"readable was not asked", len(cfg.Secret.Links))
		return
	}
	// The question is put by being those accounts, which runuser needs root for.
	// Unprivileged, runuser fails for every path, and reading that as the answer
	// reported the broker unable to open files it was serving values from: a
	// question that cannot be asked is unasked, not a verdict, which is the
	// contract every other boundary check keeps.
	if os.Geteuid() != 0 {
		report.unaskedf(name, len(cfg.Secret.Links), "whether the %d linked "+
			"file(s) are readable by %s and not by %s can only be checked as those "+
			"accounts. Run doctor as root", len(cfg.Secret.Links),
			opts.BrokerUser, opts.ExecUser)
		return
	}

	var unreadable, reachable, absent []string
	for _, link := range cfg.Secret.Links {
		switch {
		case !hostfs.Exists(link.Path):
			absent = append(absent, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		case !asaccount.CanRead(opts.BrokerUser, link.Path):
			entry := fmt.Sprintf("%s (%s)", link.Ref, link.Path)
			// The directory, where that is what refuses: the remedy below is about
			// the file's own group and mode, and neither is the problem here.
			if dir := asaccount.BlockingDir(opts.BrokerUser, link.Path); dir != "" {
				entry += fmt.Sprintf(", which it cannot enter %s to reach", dir)
			}
			unreadable = append(unreadable, entry)
		case asaccount.CanRead(opts.ExecUser, link.Path):
			reachable = append(reachable, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		}
	}

	switch {
	case len(reachable) > 0:
		report.addf(name, StatusFailed, "%s can read a linked file directly, so "+
			"a brokered command reaches the plaintext without asking for the ref, and the "+
			"redactor never sees it: %s", opts.ExecUser,
			strings.Join(reachable, ", "))
	case len(unreadable) > 0:
		report.addf(name, StatusFailed, "%s cannot read a linked file, so that "+
			"ref is refused while the plaintext is still on disk. A tool that rewrites "+
			"its own file changes the group; `sudo chgrp %s PATH && sudo chmod g+r PATH` "+
			"puts it back: %s", opts.BrokerUser, asaccount.GroupNameOf(opts.BrokerUser),
			strings.Join(unreadable, ", "))
	case len(absent) > 0:
		report.addf(name, StatusFailed, "%d linked file(s) are readable by %s "+
			"alone; %d are missing, so those refs answer nothing. Either the credential "+
			"has left the machine and the entry should go with `faramir link rm REF`, or "+
			"the home holding it is not mounted: %s",
			len(cfg.Secret.Links)-len(absent), opts.BrokerUser, len(absent),
			strings.Join(absent, ", "))
	default:
		report.addf(name, StatusOK, "%d linked file(s) readable by %s and not by %s",
			len(cfg.Secret.Links), opts.BrokerUser, opts.ExecUser)
	}
}
