// Package faramir holds the files `faramir init` writes to a host: the systemd
// units, the base config, the agent hook and its deny list, the docs and the
// licence.  Embedded, so installing needs nothing but the binary.
package faramir

import "embed"

// Assets is every file faramir writes to a host, by `init` or by
// `init-project`.  The units and the base config are
// text/templates: the shared group and the service uids are named in both, and
// rendering them from one set of values is what keeps them from disagreeing.
//
//go:embed etc systemd agent docs README.md LICENSE
var Assets embed.FS
