package sharetree

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
	aclExecute  = 0x01
	aclNoID     = ^uint32(0)
)

type accessACL struct {
	owner, group, other, mask uint16
	users, groups             map[uint32]uint16
}

// Linux stores access ACLs as a little-endian version header followed by
// eight-byte entries: include/uapi/linux/posix_acl_xattr.h in the kernel.
func parseAccessACL(data []byte) (accessACL, error) {
	acl := accessACL{mask: 7, users: map[uint32]uint16{}, groups: map[uint32]uint16{}}
	if len(data) < 28 || (len(data)-4)%8 != 0 || binary.LittleEndian.Uint32(data) != 2 {
		return acl, errors.New("invalid access ACL header or length")
	}
	seen := map[uint16]bool{}
	for offset := 4; offset < len(data); offset += 8 {
		tag := binary.LittleEndian.Uint16(data[offset:])
		perm := binary.LittleEndian.Uint16(data[offset+2:])
		id := binary.LittleEndian.Uint32(data[offset+4:])
		if perm > 7 {
			return acl, errors.New("invalid access ACL permissions")
		}
		if tag == aclUser || tag == aclGroup {
			entries := acl.users
			if tag == aclGroup {
				entries = acl.groups
			}
			if _, exists := entries[id]; exists || id == aclNoID {
				return acl, errors.New("invalid or duplicate access ACL qualifier")
			}
			entries[id] = perm
			continue
		}
		if seen[tag] || id != aclNoID {
			return acl, errors.New("invalid or duplicate access ACL entry")
		}
		seen[tag] = true
		switch tag {
		case aclUserObj:
			acl.owner = perm
		case aclGroupObj:
			acl.group = perm
		case aclMask:
			acl.mask = perm
		case aclOther:
			acl.other = perm
		default:
			return acl, errors.New("unknown access ACL entry")
		}
	}
	if !seen[aclUserObj] || !seen[aclGroupObj] || !seen[aclOther] ||
		((len(acl.users) > 0 || len(acl.groups) > 0) && !seen[aclMask]) {
		return acl, errors.New("missing required access ACL entry")
	}
	return acl, nil
}

// POSIX ACL checks select owner, named user, matching groups, then other.
// A matching group denied by its permissions or mask never falls back to other.
func (a accessACL) canEnter(who entrant, st *syscall.Stat_t) bool {
	if who.uid >= 0 {
		if uint32(who.uid) == st.Uid {
			return a.owner&aclExecute != 0
		}
		if perm, exists := a.users[uint32(who.uid)]; exists {
			return perm&a.mask&aclExecute != 0
		}
	}
	matched := slices.Contains(who.gids, int(st.Gid))
	var permissions uint16
	if matched {
		permissions = a.group
	}
	for _, gid := range who.gids {
		if perm, exists := a.groups[uint32(gid)]; exists {
			matched = true
			permissions |= perm
		}
	}
	if matched {
		return permissions&a.mask&aclExecute != 0
	}
	return a.other&aclExecute != 0
}

func canTraverse(who entrant, info os.FileInfo, directory *os.File) (bool, bool, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false, errors.New("cannot read ownership")
	}
	acl, present, err := readAccessACL(directory)
	if err != nil {
		return false, false, err
	}
	if !present {
		return who.canEnter(st, info.Mode().Perm()), false, nil
	}
	return acl.canEnter(who, st), true, nil
}

func readAccessACL(file *os.File) (accessACL, bool, error) {
	// Most entries have no ACL, or an ACL fitting this small buffer. Larger
	// values get a bounded size query; a racing enlargement fails closed.
	data := make([]byte, 256)
	n, err := unix.Fgetxattr(int(file.Fd()), "system.posix_acl_access", data)
	if errors.Is(err, unix.ERANGE) {
		n, err = unix.Fgetxattr(int(file.Fd()), "system.posix_acl_access", nil)
		if err != nil {
			return accessACL{}, false, fmt.Errorf("read access ACL size: %w", err)
		}
		if n > 65536 || n < 0 {
			return accessACL{}, false, fmt.Errorf("invalid access ACL size %d", n)
		}
		data = make([]byte, n)
		n, err = unix.Fgetxattr(int(file.Fd()), "system.posix_acl_access", data)
		if err != nil {
			return accessACL{}, false, fmt.Errorf("read access ACL: %w", err)
		}
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return accessACL{}, false, nil
	}
	if err != nil {
		return accessACL{}, false, fmt.Errorf("read access ACL: %w", err)
	}
	acl, err := parseAccessACL(data[:n])
	if err != nil {
		return accessACL{}, false, err
	}
	return acl, true, nil
}

func (a accessACL) bytes() []byte {
	data := binary.LittleEndian.AppendUint32(nil, 2)
	appendEntry := func(tag, permissions uint16, id uint32) {
		data = binary.LittleEndian.AppendUint16(data, tag)
		data = binary.LittleEndian.AppendUint16(data, permissions)
		data = binary.LittleEndian.AppendUint32(data, id)
	}
	appendEntry(aclUserObj, a.owner, aclNoID)
	for _, id := range slices.Sorted(maps.Keys(a.users)) {
		appendEntry(aclUser, a.users[id], id)
	}
	appendEntry(aclGroupObj, a.group, aclNoID)
	for _, id := range slices.Sorted(maps.Keys(a.groups)) {
		appendEntry(aclGroup, a.groups[id], id)
	}
	appendEntry(aclMask, a.mask, aclNoID)
	appendEntry(aclOther, a.other, aclNoID)
	return data
}

// Group bits in stat describe the ACL mask. Update GROUP_OBJ explicitly and
// clamp named entries to their old effective rights before expanding that mask.
func sharedAccessACL(mode os.FileMode, original accessACL) (os.FileMode, accessACL) {
	updated := accessACL{
		owner: uint16(mode.Perm() >> 6), other: uint16(mode.Perm() & 7),
		group: original.group&original.mask | 6,
		users: map[uint32]uint16{}, groups: map[uint32]uint16{},
	}
	executable := mode.IsDir() || mode.Perm()&0o101 != 0 || original.group&original.mask&1 != 0
	for id, permissions := range original.users {
		updated.users[id] = permissions & original.mask
		executable = executable || updated.users[id]&1 != 0
	}
	for id, permissions := range original.groups {
		updated.groups[id] = permissions & original.mask
		executable = executable || updated.groups[id]&1 != 0
	}
	if executable {
		updated.group |= aclExecute
	}
	updated.mask = updated.group
	for _, permissions := range updated.users {
		updated.mask |= permissions
	}
	for _, permissions := range updated.groups {
		updated.mask |= permissions
	}
	mode = mode&^0o070 | os.FileMode(updated.mask)<<3
	return mode, updated
}

func applySharing(uid, gid int, mode os.FileMode, acl *accessACL, file *os.File) error {
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if acl != nil {
		if err := unix.Fsetxattr(int(file.Fd()), "system.posix_acl_access", acl.bytes(), 0); err != nil {
			return fmt.Errorf("write access ACL: %w", err)
		}
	}
	// The ACL is normalized first, so this chmod cannot unmask dormant named
	// permissions. It also restores special bits cleared by chown.
	return file.Chmod(mode)
}
