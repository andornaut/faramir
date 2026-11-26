package enrol

import "strings"

// The installed config describes the generated unit, not effective operator
// overrides. Sharing filesystem permissions does not change the unit sandbox.
func warnExecutorWrites(report *Report, installedSudo bool, dir string) {
	if installedSudo || strings.HasPrefix(dir, "/home/") {
		return
	}
	report.Warnf("group access to %s may not permit brokered writes outside /home\n"+
		"  without --allow-sudo, the generated executor uses ProtectSystem=strict. Check the effective unit and operator drop-ins before changing ReadWritePaths=", dir)
}
