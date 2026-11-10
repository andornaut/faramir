package sharetree

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestACLSharingGrantsGroupAccessWithoutUnmaskingNamedRights(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "source")
	private := filepath.Join(root, "private")
	for _, path := range []string{public, private} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uid := uint32(os.Getuid() + 100)
	gid := uint32(os.Getgid() + 100)
	fixtureACL := func(owner, group uint16) []byte {
		return aclBytes(
			aclEntry{aclUserObj, owner, aclNoID},
			aclEntry{aclUser, 7, uid},
			aclEntry{aclGroupObj, group, aclNoID},
			aclEntry{aclGroup, 7, gid},
			aclEntry{aclMask, 4, aclNoID},
			aclEntry{aclOther, 0, aclNoID},
		)
	}
	for _, path := range []string{root, public, private} {
		owner := uint16(6)
		if path == root {
			owner = 7
		}
		group := uint16(4)
		if path != public {
			group = 0
		}
		data := fixtureACL(owner, group)
		if err := unix.Setxattr(path, "system.posix_acl_access", data, 0); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				t.Skip("filesystem does not support POSIX access ACLs")
			}
			t.Fatal(err)
		}
	}
	readACL := func(path string) accessACL {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()
		acl, present, err := readAccessACL(file)
		if err != nil || !present {
			t.Fatalf("read ACL on %s: %v, %v", path, acl, err)
		}
		return acl
	}
	privateBefore := readACL(private).bytes()
	group, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Dir: root, Operator: "root", Group: group.Name,
		PreservePrivate: true, PreserveOwner: true}
	if _, err := Share(opts); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, public} {
		acl := readACL(path)
		want := uint16(6)
		if path == root {
			want = 7
		}
		if acl.group != want || acl.mask != want {
			t.Errorf("%s group=%o mask=%o, want %o", path, acl.group, acl.mask, want)
		}
		if acl.users[uid] != 4 || acl.groups[gid] != 4 {
			t.Errorf("%s unmasked named rights: user=%o group=%o", path, acl.users[uid], acl.groups[gid])
		}
	}
	if got := readACL(private).bytes(); !bytes.Equal(got, privateBefore) {
		t.Error("sharing changed a private ACL whose group object cannot read")
	}
	if result, err := Share(opts); err != nil || result.Changed != 0 {
		t.Errorf("repeat ACL share = %+v, error %v", result, err)
	}
}
