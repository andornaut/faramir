package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// diagnoseLogRotation asks whether anything bounds the audit log. The record
// cap bounds one record and nothing in faramir bounds the file: rotation is
// logrotate's, which has to be installed, has to name this log, and has to be
// run on it. A record carries a brokered command's output, so an agent that
// prints enough fills the disk, and a full disk is where brokered commands stop
// running at all.
//
// Every question is asked of what is on disk: a rule bounding the path
// config.toml named before it was edited, and a rule no run of logrotate ever
// reads, both look like a working rotation from the install's side. The last
// two read logrotate's state and the log itself, which belong to root and to
// the broker, so a caller without root is told they went unasked rather than
// given the pass a failed stat would otherwise imply.
func diagnoseLogRotation(report *Report, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	logPath := cfg.Audit.LogPath
	if !hostfs.Exists(hostlayout.LogrotateConfig) {
		report.addf("log rotation", StatusFailed, "%s does not exist, so nothing "+
			"bounds %s. Re-run `faramir init`, or bound it some other way",
			hostlayout.LogrotateConfig, logPath)
		return
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		report.addf("log rotation", StatusFailed, "%s exists but logrotate is "+
			"not installed, so %s grows without a ceiling. Install logrotate, or bound "+
			"that file some other way", hostlayout.LogrotateConfig, logPath)
		return
	}

	// The rule has to name the file the broker appends to. Both are rendered
	// from one layout, so they part only where [audit] log_path moved after init,
	// leaving the rule bounding a path nothing writes.
	named, err := logrotateLogs(hostlayout.LogrotateConfig)
	switch {
	case err != nil:
		report.addf("log rotation", StatusFailed, "%s cannot be read (%v), so "+
			"whether anything bounds %s is unknown", hostlayout.LogrotateConfig, err, logPath)
		return
	case len(named) == 0:
		report.addf("log rotation", StatusWarn, "%s names no log file, so it is "+
			"empty or in a form this check cannot read. Confirm it covers %s with "+
			"`logrotate -d %s`", hostlayout.LogrotateConfig, logPath, hostlayout.LogrotateConfig)
		return
	case !logrotateCovers(named, logPath):
		report.addf("log rotation", StatusFailed, "%s bounds %s but the broker "+
			"appends to %s, so nothing bounds the log this host writes. Point [audit] "+
			"log_path back at the rotated file, or re-run `faramir init`", hostlayout.LogrotateConfig, strings.Join(named, ", "), logPath)
		return
	}

	// What logrotate has processed, the only evidence that the rule is read rather
	// than merely installed: one the include line does not reach, or that a syntax
	// error earlier in the set abandons, is skipped every run.
	statePath := firstExisting(hostlayout.LogrotateStatePaths)
	if statePath == "" {
		report.addf("log rotation", StatusWarn, "logrotate keeps no state at "+
			"%s, so it has not run on this host and the rule bounding %s has never been "+
			"applied. Check the logrotate timer or cron job",
			strings.Join(hostlayout.LogrotateStatePaths, " or "), logPath)
		return
	}
	rotated, err := logrotateStateLogs(statePath)
	switch {
	case os.IsPermission(err):
		report.unaskedf("log rotation", 1, "the rest was not checked: %s says "+
			"which logs logrotate has processed and %s is the broker's, and only root can "+
			"read them. %s does name %s. Run doctor as root",
			statePath, logPath, hostlayout.LogrotateConfig, logPath)
		return
	case err != nil:
		report.addf("log rotation", StatusFailed, "%s cannot be read (%v), so "+
			"whether logrotate has ever applied %s is unknown",
			statePath, err, hostlayout.LogrotateConfig)
		return
	case !slices.Contains(rotated, logPath):
		report.addf("log rotation", StatusWarn, "%s names %d logs and not %s, "+
			"so logrotate has not applied the rule to it. A first run that has not "+
			"happened yet is the usual reason; otherwise check the logrotate timer or "+
			"cron job",
			statePath, len(rotated), logPath)
		return
	}

	// The rule rotates at 16MB, so a log far past it is one logrotate is not being
	// run on. A multiple rather than the size itself: rotation is scheduled, so a
	// log over it between two runs is ordinary.
	const rotateSize = 16 << 20
	info, err := os.Stat(logPath)
	switch {
	case os.IsPermission(err):
		report.unaskedf("log rotation", 1, "the last check needs root: %s is "+
			"the broker's, so only root can read its size. %s does name it, and %s "+
			"records that logrotate has applied the rule. Run doctor as root",
			logPath, hostlayout.LogrotateConfig, statePath)
		return
	// Absent is not a fault: the rule is missingok and the broker opens the file
	// with O_CREATE, so the next record makes it again.
	case err == nil && info.Size() > 4*rotateSize:
		report.addf("log rotation", StatusWarn, "%s is %d bytes, well past the "+
			"%d the rule rotates at, so logrotate is installed but is not being run on "+
			"it. Check the logrotate timer or cron job",
			logPath, info.Size(), rotateSize)
		return
	}
	report.addf("log rotation", StatusOK, "%s bounds %s, logrotate is installed to "+
		"apply it, and %s records that it has", hostlayout.LogrotateConfig, logPath, statePath)
}

// logrotateLogs is the log files a rule file names: every path outside a
// directive block, which is where logrotate takes its file list from. A parser
// rather than `logrotate -d`, whose output is prose that differs between
// versions. Blocks are skipped by brace depth, so a postrotate script carrying
// braces of its own can hide a path from this; the caller reports finding none
// as a rule it could not read.
func logrotateLogs(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var logs []string
	depth := 0
	for line := range strings.SplitSeq(string(body), "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		for field := range strings.FieldsSeq(line) {
			// logrotate lexes the brace as its own token, so a path can carry one
			// with no space between them.
			if trimmed, ok := strings.CutSuffix(field, "{"); ok {
				if depth == 0 && trimmed != "" {
					logs = append(logs, unquoteField(trimmed))
				}
				depth++
				continue
			}
			switch {
			case field == "}":
				depth = max(depth-1, 0)
			case depth > 0:
				// A directive rather than a path.
			default:
				logs = append(logs, unquoteField(field))
			}
		}
	}
	return logs, nil
}

// logrotateCovers reports whether a rule naming these logs covers the one the
// broker writes. Globs count: a rule may name /var/log/faramir/*.log, which
// bounds audit.log without spelling it.
func logrotateCovers(named []string, logPath string) bool {
	for _, candidate := range named {
		if candidate == logPath {
			return true
		}
		if matched, err := filepath.Match(candidate, logPath); err == nil && matched {
			return true
		}
	}
	return false
}

// logrotateStateLogs is every log logrotate's state file names, which is every
// log it has processed. One line per log, the path first and quoted since
// version 2, then the date it was last rotated, which is not read here: under
// notifempty a quiet log is never rotated, so the date says how busy the host
// has been rather than whether the rule is applied.
func logrotateStateLogs(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var logs []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "logrotate state") {
			continue
		}
		if strings.HasPrefix(line, `"`) {
			// A quoted path may hold spaces, so it ends at its own quote rather
			// than at the first field boundary.
			if end := strings.IndexByte(line[1:], '"'); end >= 0 {
				logs = append(logs, line[1:end+1])
				continue
			}
		}
		logs = append(logs, strings.Fields(line)[0])
	}
	return logs, nil
}

// firstExisting is the first of these paths this host has, or "" for none.
func firstExisting(paths []string) string {
	for _, path := range paths {
		if hostfs.Exists(path) {
			return path
		}
	}
	return ""
}

// unquoteField drops one matching pair of quotes.
func unquoteField(field string) string {
	for _, quote := range []string{`"`, `'`} {
		if len(field) > 1 && strings.HasPrefix(field, quote) && strings.HasSuffix(field, quote) {
			return field[1 : len(field)-1]
		}
	}
	return field
}
