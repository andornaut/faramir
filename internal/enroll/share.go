package enroll

// Sharing the tree: the group and modes that let a brokered command run in it,
// and what the walk leaves alone.

import (
	"fmt"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/steps"
)

// keepModes is every path this enrolment writes, so sharing does not widen a
// mode this command then narrows again. Relative to the tree, which is how
// sharetree matches them.
func (p *project) keepModes() []string {
	keep := []string{}
	if rel, err := p.relativeInstructions(); err == nil {
		keep = append(keep, rel...)
	}
	// p.targets, not a second resolution: auto reads the tree, and this runs after
	// files have been written into it.
	for _, target := range p.targets {
		for _, file := range target.Files {
			keep = append(keep, file.Path)
		}
	}
	return keep
}

func (p *project) shareTree() error {
	if p.opts.DryRun {
		p.step("share tree", false, fmt.Sprintf("%s with group %s",
			p.opts.Dir, p.report.ClientGroup))
		return nil
	}
	result, err := sharetree.Share(sharetree.Options{
		Dir: p.opts.Dir, Operator: p.opts.AgentUser, Group: p.report.ClientGroup,
		Keep: p.keepModes(),
	})
	if err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	// The executor runs under ProtectSystem=strict with /home as its only
	// writable tree, so a tree outside it takes the group and then refuses every
	// write with EROFS.
	if hostlayout.HomeOf(p.opts.Dir) == "" {
		p.warnf("%s is outside /home, the only tree faramir-exec may write, so a "+
			"brokered command gets EROFS on every write there. Add a drop-in "+
			"extending ReadWritePaths= on faramir-exec.service",
			p.opts.Dir)
	}
	// What it altered, not whether it ran: the first run rewrites the ownership
	// and mode of every file in the tree, and reporting that as no change would
	// tell anything reading Changed that a regrouped tree was left alone.
	//
	// What was held back is named alongside the count, this being the one command
	// that changes a path it does not own: a bare "1200 paths regrouped" does not
	// say that the agent's own files kept their mode and their directories were
	// closed to unlink by anyone but their owner.
	detail := steps.DetailWithCount(fmt.Sprintf("%s with group %s, setgid, "+
		"owner %s", p.opts.Dir, p.report.ClientGroup, p.opts.AgentUser), result.Changed)
	if result.Kept > 0 {
		detail += fmt.Sprintf("; %d agent file(s) left at their own mode, in %d "+
			"sticky directory(ies)", result.Kept, result.Sticky)
	}
	p.step("share tree", result.Changed > 0, detail)
	return nil
}
