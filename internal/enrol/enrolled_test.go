package enrol

import (
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// The record is advisory and is written by more than one release, so a
// directory it names is not proof that enrolling it would be allowed today. An
// entry for one of faramir's own directories had every `init` writing an
// agent's settings back into it, after an operator had cleaned them out and
// after `enrol` had started refusing to make such an entry at all.
func TestARecordedTreeIsHeldToWhatAnEnrolmentWouldAllow(t *testing.T) {
	for _, dir := range []string{
		"/var/lib/" + hostlayout.DefaultBrokerUser,
		"/var/lib/" + hostlayout.DefaultKeeperUser,
		"/var/lib/" + hostlayout.DefaultExecUser,
		"/etc/faramir",
		"/etc/faramir/secrets",
		"/var/log/faramir",
	} {
		if err := RefuseInstallDirs(dir, "/etc/faramir"); err == nil {
			t.Errorf("a recorded %s would be written into: enrol refuses to "+
				"enrol it, and the step that reads the record asks the same question", dir)
		}
	}
	// The ordinary case the check must not reach.
	if err := RefuseInstallDirs("/home/op/project", "/etc/faramir"); err != nil {
		t.Errorf("a recorded project tree was refused: %v", err)
	}
}
