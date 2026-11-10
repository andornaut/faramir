package enrol

import (
	"errors"
	"fmt"
	"os"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/sharetree"
)

// ShareOnly grants filesystem access without configuring or recording agents.
// Group and Dir must be explicit. Descendants without group read permission
// retain their group and mode, and private directories are not visited.
func ShareOnly(opts Options) (Report, error) {
	report := Report{ClientGroup: opts.ClientGroup, DryRun: opts.DryRun}
	if opts.Dir == "" || opts.ClientGroup == "" {
		return report, errors.New("name a directory and a group")
	}
	if os.Geteuid() != 0 && !opts.DryRun {
		return report, errors.New("must run as root")
	}
	dir, err := sharetree.Resolve(opts.Dir)
	if err != nil {
		return report, err
	}
	report.Dir = dir
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return report, fmt.Errorf("no directory at %s", dir)
	}
	if err := refuseOversharing("share", opts.AgentUser, dir); err != nil {
		return report, err
	}
	if err := refuseInstallDirs("share", opts.ConfigDir, dir); err != nil {
		return report, err
	}
	cfg, err := config.Load(config.FileIn(opts.ConfigDir))
	if err != nil {
		return report, err
	}
	exclude, err := shareProtection(cfg)
	if err != nil {
		return report, err
	}
	if exclude(dir) {
		return report, fmt.Errorf("refusing to share protected path %s", dir)
	}
	share := sharetree.Options{
		Dir: dir, Operator: opts.AgentUser, Group: opts.ClientGroup,
		PreservePrivate: true, PreserveOwner: true, Exclude: exclude,
	}
	blocked, err := sharetree.Traversable(share)
	if err != nil {
		return report, err
	}
	if len(blocked) > 0 {
		return report, fmt.Errorf("%s not shared: %s cannot enter %s\n  open them, then run this again:\n%s",
			dir, opts.ClientGroup, sharetree.Describe(blocked), sharetree.Fix(blocked, opts.ClientGroup))
	}
	report.LogTo(opts.Log)
	if opts.DryRun {
		report.Skip("share tree", fmt.Sprintf("%s with group %s", dir, opts.ClientGroup))
		return report, nil
	}
	share.Progress = func(walked int) {
		report.Progress("share tree", fmt.Sprintf("%s, %d path(s) so far", dir, walked))
	}
	result, err := sharetree.Share(share)
	report.Record("share tree", result.Changed > 0,
		fmt.Sprintf("%s with group %s, %d path(s) changed; private descendants and owners retained",
			dir, opts.ClientGroup, result.Changed))
	return report, err
}

func shareProtection(cfg *config.Config) (func(string) bool, error) {
	var protected []func(string) bool
	for _, rule := range denyrules.For("", nil, cfg.Ssh.Key, cfg.Secret) {
		for _, subject := range rule.Subjects {
			pattern, err := denyrules.Compile(subject)
			if err != nil {
				return nil, err
			}
			protected = append(protected, pattern.MatchString)
		}
	}
	return func(path string) bool {
		for _, matches := range protected {
			if matches(path) {
				return true
			}
		}
		return false
	}, nil
}
