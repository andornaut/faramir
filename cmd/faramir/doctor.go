package main

// `faramir doctor`: what it asks of a host, and how the answers are laid out
// for a reader. It acts on files rather than through the broker, but it asks a
// running one where the install is; see askBroker.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/doctor"
	"github.com/andornaut/faramir/internal/termsafe"
	"github.com/andornaut/faramir/internal/termui"
)

type doctorFlags struct {
	clientGroup  string
	secretsGroup string
	brokerUser   string
	keeperUser   string
	execUser     string
	asJSON       bool
	when         string
}

func newDoctorCmd() *cobra.Command {
	var f doctorFlags
	c := &cobra.Command{
		Use:     "doctor [options]",
		Short:   "Check the install and report what is wrong",
		GroupID: groupProvisioning,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runDoctor(f)) },
	}
	fl := c.Flags()
	// No --agent-user, as on every command but `init`: doctor reports on an
	// install, and the account that install belongs to is one of the things it
	// reads rather than one it is told.
	// Empty rather than the install defaults: doctor reads what this host runs
	// out of the units, the config and the secrets directory, and a default here
	// would answer about accounts a host installed with other names does not
	// have. Each is an override for a host whose install is not this one.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"override the group admitted to the broker socket, instead of reading [server] allowed_group")
	fl.StringVar(&f.secretsGroup, "secrets-group", "",
		"override the group owning the ciphertext, instead of reading it off <config-dir>/secrets")
	fl.StringVar(&f.brokerUser, "broker-user", "",
		"override the account the broker runs as, instead of reading faramir-broker.service")
	fl.StringVar(&f.keeperUser, "keeper-user", "",
		"override the account that holds the age key, instead of reading faramir-keeper.service")
	fl.StringVar(&f.execUser, "exec-user", "",
		"override the account brokered commands run as, instead of reading faramir-exec.service")
	fl.BoolVar(&f.asJSON, "json", false, "print the findings as JSON")
	addColorFlag(c, &f.when)
	return c
}

// operatorFromConfig is operatorName with the install's own answer behind it.
//
// `init` records the account the agent runs as in [server] agent_user, so a
// host that has been provisioned has written down who it belongs to. Reached
// only where operatorName has nothing: root with no SUDO_USER, which is a
// container, `su -`, cron, or a configuration manager's become, and a brokered
// run whose SUDO_USER named one of faramir's own accounts. Without it those runs
// skipped every check that asks what the agent account can reach and told the
// operator to pass a flag naming what the config already said.
//
// Behind SUDO_USER rather than in front of it: a person running `sudo faramir
// doctor` is answering the same question in the present tense, and a config
// that has gone stale should not outrank them.
func operatorFromConfig(configFile string) string {
	// Once, and for both steps: the recorded answer is held to the same accounts
	// the resolved one is, or a config naming a service account would pass where
	// SUDO_USER naming it does not.
	refused := notTheOperator()
	if name := operatorName(refused, ""); name != "" {
		return name
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return ""
	}
	if refused[cfg.Server.AgentUser] {
		return ""
	}
	return cfg.Server.AgentUser
}

// recordedOperator is operatorFromConfig the other way round, for a command that
// rewrites the config without being `init`: what [server] agent_user records
// wins, and the environment does not get a say.
//
// `init` decides who the host belongs to; every other command that writes the
// config re-renders the whole of it, so one that resolved the operator afresh
// would rename the host's owner as a side effect of adding an entry. A brokered
// `sudo faramir block add` is where that lands: sudo sets SUDO_USER to the
// executor, the rewrite records that account as the operator, and every path
// rule is then rendered against its home. The rules keep the absolute spelling
// and lose the `~`, `$HOME` and `${HOME}` ones of every path under the
// operator's own home, which is silent, because dropping a spelling is not a
// step that failed.
//
// No flag reaches here, these commands having none: one that agreed with the
// record changed nothing and one that disagreed was refused, so the whole of
// what it could do was fail. `faramir init --agent-user` is the one place an
// operator is named.
//
// The fallback is for an install whose config records nothing, which is one
// `init` has not finished: there is no recorded answer to prefer, so this is the
// resolution every other command uses. A config that will not load records
// nothing either, and is not reported here: every caller writes that same file a
// moment later and fails with an error naming it, where this would name only the
// operator it could not read.
//
// A recorded service account is not an answer to keep. It is what this prevents
// being written, so a host that already carries one is repaired by the next run
// rather than held at it.
func recordedOperator(configFile string) string {
	refused := notTheOperator()
	if cfg, err := config.Load(configFile); err == nil {
		// Held to being an answer as well as loading: a config that records no
		// operator, or one this refuses, has nothing to prefer over the resolution
		// below. Checked for empty rather than left to the refusal set, which does
		// not carry "" and would take an unrecorded operator for a recorded one.
		if recorded := cfg.Server.AgentUser; recorded != "" && !refused[recorded] {
			return recorded
		}
	}
	return operatorName(refused, "")
}

func runDoctor(f doctorFlags) int {

	paint, bad := termui.PaletteFor("doctor", f.when)
	if bad != 0 {
		return bad
	}
	// Before the round trip below, which changes what it would report: opening
	// the broker socket activates the service, and that starts the keeper and
	// executor sockets it Requires=.
	sockets := doctor.SampleSockets()
	// One round trip: the same answer decides which install this is and whether
	// the daemons are running the code that was installed.
	//
	// Always asked, including when $FARAMIR_CONFIG already says which install.
	// The variable answers "which install" and nothing else: skipping the round
	// trip on it would make every check that needs the broker's version report
	// that the broker did not answer, when it was never asked. That opening the
	// socket activates the service is a real cost -- a stopped daemon is started
	// by the diagnosis -- but a report that is quietly wrong about what it asked
	// is worse than one that names a broker the asking started.
	broker := askBroker(socketDefault())
	configFile, err := findConfigFile(broker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir doctor: %v\n", err)
		return 1
	}
	dir := filepath.Dir(configFile)
	report := doctor.Diagnose(doctor.Options{
		ConfigDir:     dir,
		BrokerVersion: broker.version,
		BrokerBuild:   broker.build,
		SocketStates:  sockets,
		AgentUser:     operatorFromConfig(configFile),
		ClientGroup:   f.clientGroup,
		BrokerUser:    f.brokerUser,
		KeeperUser:    f.keeperUser,
		ExecUser:      f.execUser,
		SecretsGroup:  f.secretsGroup,
	})
	if f.asJSON {
		if code := printJSON("doctor", report); code != 0 {
			return code
		}
	} else {
		printDiagnosis(os.Stdout, paint, report)
	}
	if report.Failed {
		return 1
	}
	return 0
}

// printDiagnosis lays the findings out as status, check, detail. The check is
// named once per run of findings that share it, and the detail wraps under
// itself rather than being cut at the terminal edge.
func printDiagnosis(w io.Writer, paint termui.Palette, report doctor.Report) {
	statusWidth := columns(statusColumn(doctor.StatusFailed)) // the longest
	name := 0
	for _, finding := range report.Findings {
		name = max(name, len(finding.Name))
	}
	indent := statusWidth + 2 + name + 2
	counts := map[doctor.Status]int{}
	previous := ""
	for _, finding := range report.Findings {
		counts[finding.Status]++
		label := finding.Name
		if label == previous {
			label = ""
		}
		previous = finding.Name
		// A finding with no detail is still a line.
		//
		// Escaped before it is wrapped: a detail carries a path from the config and
		// an error string from the host, and a filename may hold anything the
		// filesystem accepts. A terminal obeys what it is sent, so a carriage
		// return in one would overwrite the status it was printed beside, on the
		// one command an operator runs to find out whether the install is sound.
		// Escaping first also keeps the wrap honest, the escaped form being what
		// takes up the width.
		first, rest := "", []string(nil)
		if lines := wrapText(termsafe.Line(finding.Detail), terminalWidth()-indent); len(lines) > 0 {
			first, rest = lines[0], lines[1:]
		}
		_, _ = fmt.Fprintf(w, "%s  %-*s  %s\n", paintStatus(paint, finding.Status), name, label, first)
		for _, line := range rest {
			_, _ = fmt.Fprintf(w, "%*s%s\n", indent, "", line)
		}
	}
	if len(report.Findings) == 0 {
		return
	}
	var totals []string
	for _, status := range []doctor.Status{doctor.StatusOK, doctor.StatusNA,
		doctor.StatusWarn, doctor.StatusFailed} {
		if counts[status] > 0 {
			totals = append(totals, fmt.Sprintf("%d %s", counts[status], status))
		}
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", paint.Bold(strings.Join(totals, ", ")))
	printNotAsked(w, paint, report.NotAsked)
}

// printNotAsked says how much of the examination did not happen, outside the
// findings and the totals: a skipped check is one warn line whatever it stood
// for, so the totals alone read the same on a host barely examined.
func printNotAsked(w io.Writer, paint termui.Palette, count int) {
	if count == 0 {
		return
	}
	note := fmt.Sprintf("%d more check(s) were not made, so the totals above are not "+
		"the whole examination.", count)
	if os.Geteuid() != 0 {
		// "Most", not "each": want of systemd, of sops on the PATH, or of a broker
		// holding values is counted here too, and root changes none of those.
		note += " Most of them have to read a file or run a command as an account " +
			"that is not yours: the operator can re-run doctor as root, and what " +
			"root does not answer stays listed with its own reason."
	}
	_, _ = fmt.Fprintln(w)
	for _, line := range wrapText(note, terminalWidth()) {
		_, _ = fmt.Fprintf(w, "%s\n", paint.Warn(line))
	}
}

// statusColumn is the glyph and the word: the glyph makes the column scannable,
// the word survives a pipe into a log or a grep for "failed". The glyph is
// dropped where the locale is not UTF-8.
func statusColumn(status doctor.Status) string {
	mark := map[doctor.Status]string{
		doctor.StatusOK:     "✓", // check mark
		doctor.StatusNA:     "·", // middle dot: neither asserted nor withheld
		doctor.StatusWarn:   "!",
		doctor.StatusFailed: "✗", // ballot X
	}[status]
	if mark == "" || !unicodeLocale() {
		return fmt.Sprintf("%-6s", status)
	}
	return fmt.Sprintf("%s %-6s", mark, status)
}

// columns is a string's width on screen. Every glyph above is one column wide,
// so runes are the answer and len would count a check mark as three.
func columns(text string) int { return utf8.RuneCountInString(text) }

// unicodeLocale reports whether the terminal was told to expect UTF-8, in the
// order the C library reads these.
func unicodeLocale() bool {
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(name); value != "" {
			return strings.Contains(strings.ToUpper(value), "UTF-8") ||
				strings.Contains(strings.ToUpper(value), "UTF8")
		}
	}
	return false
}

func paintStatus(paint termui.Palette, status doctor.Status) string {
	text := statusColumn(status)
	switch status {
	case doctor.StatusOK:
		return paint.OK(text)
	// Dim rather than a colour of its own: nothing was claimed, so the line is
	// there to be read past.
	case doctor.StatusNA:
		return paint.Dim(text)
	case doctor.StatusWarn:
		return paint.Warn(text)
	case doctor.StatusFailed:
		return paint.Bad(text)
	default:
		// A status this build does not know is the one worth looking at.
		return paint.Bad(text)
	}
}

// wrapText breaks a detail into lines that fit. Words only, so a path stays
// copyable: an over-long word overflows rather than being cut.
func wrapText(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	line := ""
	for word := range strings.FieldsSeq(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// terminalWidth is $COLUMNS, then 80. A wrong guess costs a wrapped line, so
// this needs no dependency.
func terminalWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 40 {
		return columns
	}
	return 80
}
