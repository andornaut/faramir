package sharetree

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type aclEntry struct {
	tag, permissions uint16
	id               uint32
}

func aclBytes(entries ...aclEntry) []byte {
	data := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range entries {
		data = binary.LittleEndian.AppendUint16(data, entry.tag)
		data = binary.LittleEndian.AppendUint16(data, entry.permissions)
		data = binary.LittleEndian.AppendUint32(data, entry.id)
	}
	return data
}

func TestACLTraversalRespectsIdentityMaskAndGroupPrecedence(t *testing.T) {
	data := aclBytes(
		aclEntry{aclUserObj, 0, aclNoID},
		aclEntry{aclUser, 0, 12},
		aclEntry{aclUser, 1, 13},
		aclEntry{aclGroupObj, 0, aclNoID},
		aclEntry{aclGroup, 1, 22},
		aclEntry{aclGroup, 0, 23},
		aclEntry{aclMask, 1, aclNoID},
		aclEntry{aclOther, 1, aclNoID},
	)
	acl, err := parseAccessACL(data)
	if err != nil {
		t.Fatal(err)
	}
	st := &syscall.Stat_t{Uid: 11, Gid: 21}
	for _, tc := range []struct {
		name string
		who  entrant
		mask uint16
		want bool
	}{
		{"named group grants traversal", groupEntrant(22), 1, true},
		{"mask removes named group traversal", groupEntrant(22), 0, false},
		{"matching named group cannot use other", groupEntrant(23), 1, false},
		{"owning group cannot use other", groupEntrant(21), 1, false},
		{"nonmatching group uses other", groupEntrant(24), 1, true},
		{"owner denial precedes named group", entrant{uid: 11, gids: []int{22}}, 1, false},
		{"named user denial precedes named group", entrant{uid: 12, gids: []int{22}}, 1, false},
		{"named user grants traversal", entrant{uid: 13, gids: []int{23}}, 1, true},
		{"named user respects mask", entrant{uid: 13, gids: []int{22}}, 0, false},
		{"supplemental group grants traversal", entrant{uid: 14, gids: []int{21, 22}}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl.mask = tc.mask
			if got := acl.canEnter(tc.who, st); got != tc.want {
				t.Errorf("ACL traversal = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMalformedACLsFailClosed(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{2, 0, 0, 0, 1},
		aclBytes(aclEntry{aclUserObj, 7, aclNoID}, aclEntry{aclGroupObj, 7, aclNoID}, aclEntry{aclOther, 8, aclNoID}),
		aclBytes(aclEntry{aclUserObj, 7, aclNoID}, aclEntry{aclUserObj, 7, aclNoID}, aclEntry{aclOther, 7, aclNoID}),
		aclBytes(aclEntry{aclUserObj, 7, aclNoID}, aclEntry{aclGroupObj, 7, aclNoID}, aclEntry{aclOther, 7, aclNoID}, aclEntry{aclGroup, 1, 22}),
	} {
		if _, err := parseAccessACL(data); err == nil {
			t.Errorf("accepted malformed ACL %x", data)
		}
	}
}

func TestAccessACLReadHandlesLargerThanTheInitialBuffer(t *testing.T) {
	dir := t.TempDir()
	entries := []aclEntry{{aclUserObj, 7, aclNoID}, {aclGroupObj, 4, aclNoID}}
	for id := uint32(100); id < 140; id++ {
		entries = append(entries, aclEntry{aclGroup, 4, id})
	}
	entries = append(entries, aclEntry{aclMask, 4, aclNoID}, aclEntry{aclOther, 0, aclNoID})
	if err := unix.Setxattr(dir, "system.posix_acl_access", aclBytes(entries...), 0); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("filesystem does not support POSIX access ACLs")
		}
		t.Fatal(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	acl, present, err := readAccessACL(file)
	if err != nil || !present || len(acl.groups) != 40 {
		t.Fatalf("read large ACL = %v, error %v", acl, err)
	}
}

func TestBlockersHonorNamedGroupACLTraversalWithoutRegrouping(t *testing.T) {
	home := t.TempDir()
	middle := filepath.Join(home, "worktrees")
	tree := filepath.Join(middle, "tech")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	initial := *ownershipStat(t, info)
	gid := initial.Gid + 1
	setACL := func(mask uint16) {
		t.Helper()
		data := aclBytes(
			aclEntry{aclUserObj, 7, aclNoID},
			aclEntry{aclGroupObj, 0, aclNoID},
			aclEntry{aclGroup, 1, gid},
			aclEntry{aclMask, mask, aclNoID},
			aclEntry{aclOther, 0, aclNoID},
		)
		for _, path := range []string{home, middle} {
			if err := unix.Setxattr(path, "system.posix_acl_access", data, 0); err != nil {
				if errors.Is(err, unix.EOPNOTSUPP) {
					t.Skip("filesystem does not support POSIX access ACLs")
				}
				t.Fatal(err)
			}
		}
	}
	setACL(1)
	blocked, err := blockers(home, tree, groupEntrant(int(gid)))
	if err != nil || len(blocked) != 0 {
		t.Fatalf("ACL-granted ancestors blocked = %v, error %v", blocked, err)
	}
	for _, path := range []string{home, middle} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := ownershipStat(t, info)
		if st.Uid != initial.Uid || st.Gid != initial.Gid {
			t.Errorf("traversal check changed ownership of %s", path)
		}
	}
	setACL(0)
	blocked, err = blockers(home, tree, groupEntrant(int(gid)))
	if err != nil || len(blocked) != 2 {
		t.Errorf("masked ACL ancestors blocked = %v, error %v; want both ancestors", blocked, err)
	}
}
