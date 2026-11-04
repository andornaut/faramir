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
		report.addf(name, StatusOK, "no [[secret.link]] entries")
		return
	}
	accounts, skipped := opts.askable(opts.BrokerUser, opts.ExecUser)
	if skipped || len(accounts) < 2 {
		report.unaskedf(name, len(cfg.Secret.Links), "broker or executor account "+
			"unknown; %d linked file(s) not checked", len(cfg.Secret.Links))
		return
	}
	// The question is put by being those accounts, which runuser needs root for.
	// Unprivileged, runuser fails for every path, and reading that as the answer
	// reported the broker unable to open files it was serving values from: a
	// question that cannot be asked is unasked, not a verdict, which is the
	// contract every other boundary check keeps.
	if os.Geteuid() != 0 {
		report.unaskedf(name, len(cfg.Secret.Links), "%d linked file(s) not "+
			"checked; run doctor as root", len(cfg.Secret.Links))
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
				entry += fmt.Sprintf(": cannot enter %s", dir)
			}
			unreadable = append(unreadable, entry)
		case asaccount.CanRead(opts.ExecUser, link.Path):
			reachable = append(reachable, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		}
	}

	switch {
	case len(reachable) > 0:
		report.addf(name, StatusFailed, "%s can read linked file(s) directly\n%s",
			opts.ExecUser, strings.Join(reachable, "\n"))
	case len(unreadable) > 0:
		report.addf(name, StatusFailed, "%s cannot read linked file(s); run "+
			"`sudo chgrp %s PATH && sudo chmod g+r PATH`\n%s", opts.BrokerUser,
			asaccount.GroupNameOf(opts.BrokerUser), strings.Join(unreadable, "\n"))
	case len(absent) > 0:
		report.addf(name, StatusFailed, "%d linked file(s) missing; mount the "+
			"home holding them, or run `faramir link rm REF`\n%s",
			len(absent), strings.Join(absent, "\n"))
	default:
		report.addf(name, StatusOK, "%d linked file(s), %s only",
			len(cfg.Secret.Links), opts.BrokerUser)
	}
}
