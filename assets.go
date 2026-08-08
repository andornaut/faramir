// Package faramir holds the files `faramir init` writes to a host: the systemd
// units, the base config, the agent hook and its deny list, and the docs.
//
// They are embedded rather than read from a checkout so that installing needs
// nothing but the binaries.  A consumer of the broker then has one artifact to
// get onto a host instead of a source tree whose layout it has to know.
package faramir

import "embed"

// Assets is every file init installs.  The units and the base config are
// text/templates, because the shared group and the three service uids are named
// in both the config the sockets check and the units that reach the working
// tree.  Rendering the two from one set of values is what removes the failure
// where they disagree: a broker that installs cleanly and then refuses every
// connection.
//
//go:embed etc systemd agent docs README.md
var Assets embed.FS
