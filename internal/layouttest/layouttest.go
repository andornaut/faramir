// Package layouttest builds the install layout the rendering tests render
// against. Imported only from _test.go files.
//
// One fixture rather than a copy per package: several packages render the
// shipped templates and assert what came out, and a copy that had drifted would
// have them asserting against different installs while reading as though they
// agreed.
package layouttest

import (
	"path/filepath"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// Layout moves everything off its default, so a literal left in a template
// shows up in the output.
//
// Built as a value rather than through an install's Options: what these tests
// render is what a layout produces, and going through the installer to get one
// would test its defaults along with them.
func Layout() hostlayout.Layout {
	dir := "/opt/conf"
	return hostlayout.Layout{
		AgentUser:    "operator",
		ClientGroup:  "shared",
		SecretsGroup: "store",
		BrokerUser:   "br",
		KeeperUser:   "kp",
		ExecUser:     "ex",
		// Each service account's group, named differently from the account. An
		// install defaults each pair to the same string and resolves the real one
		// before the units render, so a directive taking a group from the *User*
		// field passes on a host where they match and names the wrong group on one
		// where an adopted account's primary group is called something else.
		BrokerGroup: "brgrp",
		KeeperGroup: "kpgrp",
		ExecGroup:   "exgrp",
		ConfigDir:   dir,
		ConfigFile:  filepath.Join(dir, "config.toml"),
		BinDir:      hostlayout.DefaultBinDir,
		LibexecDir:  hostlayout.DefaultLibexecDir,
		DocDir:      hostlayout.DefaultDocDir,
		RunDir:      hostlayout.DefaultRunDir,
		LogDir:      hostlayout.DefaultLogDir,
		AgeKeyPath:  filepath.Join(dir, "age.key"),
		SSHKey:      filepath.Join(dir, "id_ed25519"),
	}
}
