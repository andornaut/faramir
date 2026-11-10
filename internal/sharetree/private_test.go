package sharetree

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestPrivatePolicyLeavesPrivateSubtreesAndSymlinksUntouched(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]os.FileMode{
		filepath.Join(root, ".env.fixture"):         0o660,
		filepath.Join(root, "source"):               0o640,
		filepath.Join(root, "private-file"):         0o600,
		filepath.Join(privateDir, "group-readable"): 0o640,
	}
	for path, mode := range paths {
		if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(out, []byte("outside"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	owners := map[string]uint32{}
	for path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		owners[path] = info.Sys().(*syscall.Stat_t).Uid
	}
	if _, err := shareTreePolicy(true, nil, -1, nil, nil, nil, root); err != nil {
		t.Fatal(err)
	}
	paths[filepath.Join(root, "source")] = 0o660
	paths[privateDir] = 0o700
	paths[out] = 0o640
	for path, want := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
		if uid, exists := owners[path]; exists && info.Sys().(*syscall.Stat_t).Uid != uid {
			t.Errorf("%s changed user ownership", path)
		}
	}
	if changed, err := shareTreePolicy(true, nil, -1, nil, nil, nil, root); err != nil || changed != 0 {
		t.Errorf("repeat share changed %d paths, error %v", changed, err)
	}
}

func TestStandaloneShareRegroupsPublicFilesAndPreservesOwners(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	groupID := os.Getgid()
	for _, gid := range groups {
		if gid != os.Getgid() {
			groupID = gid
			break
		}
	}
	if groupID == os.Getgid() {
		t.Skip("no supplementary group to verify regrouping")
	}
	group, err := user.LookupGroupId(strconv.Itoa(groupID))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	public := filepath.Join(root, "source")
	private := filepath.Join(root, ".npmrc")
	protected := filepath.Join(root, "credential-fixture")
	privateDir := filepath.Join(root, "private-dir")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(privateDir, "group-readable")
	for _, path := range []string{public, private, protected, nested} {
		if err := os.WriteFile(path, []byte("fixture"), 0o660); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
	}
	options := Options{Dir: root, Operator: "root", Group: group.Name,
		PreserveOwner: true, PreservePrivate: true,
		Exclude: func(path string) bool { return path == protected },
	}
	if _, err := Share(options); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, public, private, protected, privateDir, nested} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != uint32(os.Getuid()) {
			t.Errorf("%s owner = %d, want %d", path, st.Uid, os.Getuid())
		}
		wantGID := groupID
		if path != root && path != public {
			wantGID = os.Getgid()
		}
		if int(st.Gid) != wantGID {
			t.Errorf("%s group = %d, want %d", path, st.Gid, wantGID)
		}
		if path != root && path != public {
			wantMode := os.FileMode(0o660)
			if path == privateDir {
				wantMode = 0o700
			}
			if info.Mode().Perm() != wantMode {
				t.Errorf("%s mode = %o, want %o", path, info.Mode().Perm(), wantMode)
			}
		}
	}
	if result, err := Share(options); err != nil || result.Changed != 0 {
		t.Errorf("repeat share = %+v, error %v", result, err)
	}
}
