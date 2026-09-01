// Package doctor reads a host back and says whether the install on it works.
//
// It reads; it never writes. Provisioning is internal/install's, and the two
// are siblings rather than one calling the other: a check that could repair
// what it found would be a check that cannot report the state it repaired.
//
// What separates it from the install steps is where the answer comes from. A
// step can only know what it wrote, and a mode on a filesystem that ignores it,
// a socket regrouped afterwards, or an account added to the shared group by
// hand all leave the written answer intact. So the questions here are put to
// the host: as the account they are about, through internal/asaccount, and
// through a brokered command where only one can answer.
//
// Every check reports a Status rather than an error, and the four are a
// deliberate split. Failed is a question that was put and came back wrong. Warn
// is a question that could not be put, for want of root, runuser, systemd or a
// broker holding values, and says nothing about the install. N/a is a subject
// belonging to an arrangement this host was not installed with. A check that
// can reach its subject and cannot establish it fails rather than guessing.
package doctor
