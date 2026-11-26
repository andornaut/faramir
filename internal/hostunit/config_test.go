package hostunit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFileAppliesSystemdEnvironmentAssignments(t *testing.T) {
	const original = "/etc/faramir/config.toml"
	const moved = "/srv/project/config.toml"
	for _, tc := range []struct {
		name, override, want string
	}{
		{"generated assignment", "Environment=FARAMIR_CONFIG=" + moved, moved},
		{"quoted assignment", "Environment=\"FARAMIR_CONFIG=/srv/project/config.toml\"", moved},
		{"single quoted assignment", "Environment='FARAMIR_CONFIG=/srv/project/config.toml'", moved},
		{"assignment list", "Environment=FIRST=one \"FARAMIR_CONFIG=/srv/project/config.toml\" LAST=two", moved},
		{"assignment after quoted variable", "Environment=\"OTHER=one two\" FARAMIR_CONFIG=/srv/project/config.toml", moved},
		{"spaces around equals", "Environment = FARAMIR_CONFIG=" + moved, moved},
		{"quoted path with spaces", "Environment=\"FARAMIR_CONFIG=/srv/with space/config.toml\"", "/srv/with space/config.toml"},
		{"C escape", "Environment=FARAMIR_CONFIG=\\x2fsrv/project/config.toml", moved},
		{"C byte escapes", "Environment=FARAMIR_CONFIG=/srv/caf\\xc3\\xa9/config.toml", "/srv/café/config.toml"},
		{"Unicode escape", "Environment=FARAMIR_CONFIG=/srv/caf\\u00e9/config.toml", "/srv/café/config.toml"},
		{"space escape", "Environment=FARAMIR_CONFIG=/srv/with\\sspace/config.toml", "/srv/with space/config.toml"},
		{"unrelated variable", "Environment=OTHER=one", original},
		{"empty unrelated variable", "Environment=OTHER=", original},
		{"reset environment", "Environment=\nEnvironment=OTHER=one", ""},
		{"reset variable", "Environment=FARAMIR_CONFIG=", ""},
		{"last assignment wins", "Environment=FARAMIR_CONFIG=/srv/first/config.toml FARAMIR_CONFIG=" + moved, moved},
		{"continued list", "Environment=OTHER=one \\\n# comment in continuation\n FARAMIR_CONFIG=" + moved, moved},
		{"another section", "[Unit]\nEnvironment=FARAMIR_CONFIG=" + moved, original},
		{"environment file left alone", "EnvironmentFile=-/some/other/settings", original},
		{"overridden specifier", "Environment=FARAMIR_CONFIG=%h/config.toml\nEnvironment=FARAMIR_CONFIG=" + moved, moved},
		{"literal percent", "Environment=FARAMIR_CONFIG=/srv/100%%/config.toml", "/srv/100%/config.toml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unitDirWith(t, map[string]string{
				"svc.service":                    "[Service]\nEnvironment=FARAMIR_CONFIG=" + original + "\n",
				"svc.service.d/10-override.conf": "[Service]\n" + tc.override + "\n",
			})
			got, err := ConfigFile(Path("svc.service"))
			if err != nil || got != tc.want {
				t.Errorf("ConfigFile = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestConfigFileDropInsAreOrderedAndDoNotInheritSections(t *testing.T) {
	unitDirWith(t, map[string]string{
		"svc.service":                      "[Service]\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n",
		"svc.service.d/10-first.conf":      "[Service]\nEnvironment=FARAMIR_CONFIG=/srv/first/config.toml\n",
		"svc.service.d/20-no-section.conf": "Environment=FARAMIR_CONFIG=/srv/ignored/config.toml\n",
	})
	got, err := ConfigFile(Path("svc.service"))
	if err != nil || got != "/srv/first/config.toml" {
		t.Fatalf("ConfigFile = %q, %v; want the sectionless drop-in ignored", got, err)
	}
	last := filepath.Join(Path("svc.service")+".d", "30-last.conf")
	if err := os.WriteFile(last, []byte("[Service]\nEnvironment=\"FARAMIR_CONFIG=/srv/last/config.toml\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ConfigFile(Path("svc.service"))
	if err != nil || got != "/srv/last/config.toml" {
		t.Fatalf("ConfigFile = %q, %v; want the last drop-in", got, err)
	}
}

func TestConfigFileRefusesDeclarationsItCannotResolve(t *testing.T) {
	for _, override := range []string{
		"Environment=\"FARAMIR_CONFIG=/srv/new/config.toml",
		"Environment=\"FARAMIR_CONFIG=/srv/new/config.toml\"suffix",
		"Environment=FARAMIR_CONFIG=/srv/\\q/config.toml",
		"Environment=FARAMIR_CONFIG=%h/config.toml",
		"Environment=FARAMIR_CONFIG=relative/config.toml",
		"Environment=FARAMIR_CONFIG=/srv/new/config.toml \\",
	} {
		t.Run(override, func(t *testing.T) {
			unitDirWith(t, map[string]string{
				"svc.service":                    "[Service]\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n",
				"svc.service.d/10-override.conf": "[Service]\n" + override,
			})
			if path, err := ConfigFile(Path("svc.service")); err == nil || path != "" {
				t.Errorf("ConfigFile = %q, %v; want a refusal without a fallback", path, err)
			}
		})
	}
}

func TestConfigFileErrorsDoNotQuoteEnvironmentValues(t *testing.T) {
	unitDirWith(t, map[string]string{
		"svc.service": "[Service]\nEnvironment=\"OTHER=fixture-not-for-output\n",
	})
	_, err := ConfigFile(Path("svc.service"))
	if err == nil || strings.Contains(err.Error(), "fixture-not-for-output") ||
		!strings.Contains(err.Error(), Path("svc.service")) {
		t.Fatalf("ConfigFile error = %v; want the file and cause without its content", err)
	}
}

func TestConfigFileReportsUnreadableDropInInsteadOfTheMainUnit(t *testing.T) {
	unitDirWith(t, map[string]string{
		"svc.service": "[Service]\nUser=custom-broker\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n",
	})
	path := Path("svc.service") + ".d"
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(path, "10-unreadable.conf")
	if err := os.Symlink(t.TempDir(), bad); err != nil {
		t.Fatal(err)
	}
	got, err := ConfigFile(Path("svc.service"))
	if err == nil || got != "" || !strings.Contains(err.Error(), bad) {
		t.Errorf("ConfigFile = %q, %v; want the unreadable drop-in", got, err)
	}
	if account, err := User("svc.service"); err != nil || account != "custom-broker" {
		t.Errorf("User = %q, %v; want to preserve the readable unit's account", account, err)
	}
}

func TestConfigFileReportsAnUnreadableDropInDirectory(t *testing.T) {
	unitDirWith(t, map[string]string{
		"svc.service": "[Service]\nUser=custom-broker\nEnvironment=FARAMIR_CONFIG=/etc/faramir/config.toml\n",
	})
	path := Path("svc.service") + ".d"
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ConfigFile(Path("svc.service"))
	if err == nil || got != "" || !strings.Contains(err.Error(), path) {
		t.Errorf("ConfigFile = %q, %v; want the drop-in enumeration error", got, err)
	}
	if account, err := User("svc.service"); err != nil || account != "custom-broker" {
		t.Errorf("User = %q, %v; want to preserve the readable unit's account", account, err)
	}
}

func TestConfigFileWithNoInstalledUnitHasNoPath(t *testing.T) {
	unitDirWith(t, nil)
	if got, err := ConfigFile(Path("svc.service")); err != nil || got != "" {
		t.Errorf("ConfigFile = %q, %v; want no installed path", got, err)
	}
}
