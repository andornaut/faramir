package enrol

import "strings"

// The installed config describes the generated unit, not effective operator
// overrides. Sharing filesystem permissions does not change the unit sandbox.
func warnExecutorWrites(report *Report, installedSudo bool, dir string) {
	if installedSudo || strings.HasPrefix(dir, "/home/") {
		return
	}
	report.Warnf("%s is outside the generated executor unit's /home write allowance; group access alone may not permit brokered writes\n"+
		"  without --allow-sudo, the generated faramir-exec.service uses ProtectSystem=strict; other unit-managed writable paths may still apply\n"+
		"  check the effective unit and operator drop-ins; add the directory to ReadWritePaths= only if needed", dir)
}
