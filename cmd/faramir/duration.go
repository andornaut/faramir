package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// durationSeconds reads a duration flag. Every duration this CLI takes is
// stored and sent as whole seconds, so this is what stands between the
// spelling a caller types and the integer that travels.
//
// Two spellings, because both are already in use: a bare number is the
// seconds these flags have always taken, and a Go duration is what an operator
// or an agent types without thinking about it. `--timeout 10s` used to fail
// with strconv's own error, which names the parser rather than the flag and
// left the caller to guess that the unit was the problem.
//
// Sub-second precision is refused rather than rounded. The broker's unit is a
// second, and a request that silently became 0 or 1 would be a timeout the
// caller did not ask for; naming it is the only answer that cannot surprise.
func durationSeconds(flag, value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return seconds, checkSeconds(flag, seconds)
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s takes a duration such as 90s or 5m, or a "+
			"bare number of seconds; %q is neither", flag, value)
	}
	if d%time.Second != 0 {
		return 0, fmt.Errorf("%s takes whole seconds, so %q cannot be used as "+
			"given; use %s or round up", flag, value, d.Truncate(time.Second))
	}
	seconds := int(d / time.Second)
	return seconds, checkSeconds(flag, seconds)
}

// asDuration spells a default for --help. The defaults are kept in seconds,
// being what the config stores, and printing one as a bare number beside a
// flag that takes a duration is how a caller learns the wrong spelling.
func asDuration(seconds int) string {
	return (time.Duration(seconds) * time.Second).String()
}

// checkSeconds refuses a negative duration. Zero is not refused: it is how
// every one of these flags says "no value of my own", which the broker and the
// config read as their own default.
func checkSeconds(flag string, seconds int) error {
	if seconds < 0 {
		return fmt.Errorf("%s must not be negative; leave it out for the default", flag)
	}
	return nil
}
