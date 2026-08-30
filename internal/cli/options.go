package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.Count(value, "/") != 1 || strings.ContainsAny(value, "\\\r\n\x00") {
		return errors.New("repository must use owner/name syntax")
	}
	*s = append(*s, value)
	return nil
}

type commonTargetOptions struct {
	Organization string
	Repositories []string
}

func (o commonTargetOptions) validate() error {
	if (o.Organization == "") == (len(o.Repositories) == 0) {
		return errors.New("provide exactly one of --org or one or more --repo flags")
	}
	if strings.ContainsAny(o.Organization, "/\\\r\n\x00") {
		return errors.New("organization name is invalid")
	}
	seen := make(map[string]bool, len(o.Repositories))
	for _, repository := range o.Repositories {
		key := strings.ToLower(repository)
		if seen[key] {
			return fmt.Errorf("duplicate repository target %q", repository)
		}
		seen[key] = true
	}
	return nil
}

type investigateOptions struct {
	Targets    commonTargetOptions
	Incident   string
	From       time.Time
	To         time.Time
	Output     string
	RawLogs    bool
	Quiet      bool
	Verbose    bool
	Concurrent int
}

const investigateUsage = `Usage:
  cirewind investigate (--org ORG | --repo OWNER/REPO ...) --incident FILE \
    --from RFC3339 --to RFC3339 --out CASE_DIR [--raw-logs]

Collects read-only GitHub.com evidence for every attempt associated with the
requested half-open event window [from,to). Parent-run discovery provisionally
looks back 65 days so reruns and delayed jobs are not silently omitted.

Authentication is resolved from CIREWIND_GITHUB_TOKEN, GITHUB_TOKEN, then
GH_TOKEN. Raw logs are discarded by default because they may contain sensitive
application output despite GitHub masking. --raw-logs explicitly retains exact
bounded log objects under the manifested case raw/ directory.
`

func parseInvestigate(args []string, output io.Writer) (investigateOptions, error) {
	var result investigateOptions
	var repositories stringList
	var from, to string
	fs := flag.NewFlagSet("investigate", flag.ContinueOnError)
	configureFlagHelp(fs, output, investigateUsage)
	fs.StringVar(&result.Targets.Organization, "org", "", "GitHub organization to enumerate")
	fs.Var(&repositories, "repo", "explicit owner/repository target (repeatable)")
	fs.StringVar(&result.Incident, "incident", "", "validated incident-pack YAML")
	fs.StringVar(&from, "from", "", "inclusive incident-window start (RFC3339)")
	fs.StringVar(&to, "to", "", "exclusive incident-window end (RFC3339)")
	fs.StringVar(&result.Output, "out", "", "new case output directory")
	fs.BoolVar(&result.RawLogs, "raw-logs", false, "retain exact log objects in case raw/ (sensitive; opt-in)")
	fs.BoolVar(&result.Quiet, "quiet", false, "print only errors and final coverage")
	fs.BoolVar(&result.Verbose, "verbose", false, "print sanitized collection progress")
	fs.IntVar(&result.Concurrent, "concurrency", 4, "bounded repository collection concurrency (1-16)")
	if err := fs.Parse(args); err != nil {
		return result, err
	}
	if fs.NArg() != 0 {
		return result, fmt.Errorf("%w: investigate accepts flags only", errUsage)
	}
	result.Targets.Repositories = append([]string(nil), repositories...)
	if err := result.Targets.validate(); err != nil {
		return result, fmt.Errorf("%w: %v", errUsage, err)
	}
	if result.Incident == "" || result.Output == "" || from == "" || to == "" {
		return result, fmt.Errorf("%w: --incident, --from, --to, and --out are required", errUsage)
	}
	var err error
	if result.From, err = parseUTC(from); err != nil {
		return result, fmt.Errorf("%w: invalid --from: %v", errUsage, err)
	}
	if result.To, err = parseUTC(to); err != nil {
		return result, fmt.Errorf("%w: invalid --to: %v", errUsage, err)
	}
	if !result.From.Before(result.To) {
		return result, fmt.Errorf("%w: --from must precede --to", errUsage)
	}
	if result.Concurrent < 1 || result.Concurrent > 16 {
		return result, fmt.Errorf("%w: --concurrency must be in 1..16", errUsage)
	}
	if result.Quiet && result.Verbose {
		return result, fmt.Errorf("%w: --quiet and --verbose are mutually exclusive", errUsage)
	}
	return result, nil
}

type archiveOptions struct {
	Targets       commonTargetOptions
	Store         string
	From          *time.Time
	To            time.Time
	Since         time.Duration
	RawLogs       bool
	Quiet         bool
	Verbose       bool
	Concurrent    int
	ImportFixture string
}

const archiveUsage = `Usage:
  cirewind archive (--org ORG | --repo OWNER/REPO ...) --since DURATION --store FILE [--raw-logs]
  cirewind archive (--org ORG | --repo OWNER/REPO ...) --from RFC3339 --to RFC3339 --store FILE [--raw-logs]

Incrementally preserves compact execution facts. Raw logs are discarded by
default. --raw-logs retains exact bounded log objects in the mode-restricted
<store>.raw sidecar where the platform supports Unix permissions; the database
and sidecar then form one archive set. An
existing archive used with --since resumes from per-repository checkpoints,
overlaps new-parent discovery by 15 minutes, and refreshes retained parent run
IDs through the provisional 65-day rerun/environment-delay watch horizon.
If --since starts after a stale checkpoint, collection reports the continuity
gap and does not advance that checkpoint; extend --since to close the interval.
An explicit --from/--to scans that exact requested event interval with separate
conservative parent discovery and does not advance an existing polling
checkpoint. The internal
--import-fixture option is for harmless offline test fixtures only; the value
"synthetic" selects the built-in deterministic demonstration fixture.
`

func parseArchive(args []string, output io.Writer) (archiveOptions, error) {
	var result archiveOptions
	var repositories stringList
	var from, to, since string
	fs := flag.NewFlagSet("archive", flag.ContinueOnError)
	configureFlagHelp(fs, output, archiveUsage)
	fs.StringVar(&result.Targets.Organization, "org", "", "GitHub organization to enumerate")
	fs.Var(&repositories, "repo", "explicit owner/repository target (repeatable)")
	fs.StringVar(&since, "since", "", "initial/requested lookback; existing archives resume conservatively from checkpoints")
	fs.StringVar(&from, "from", "", "inclusive collection start (RFC3339)")
	fs.StringVar(&to, "to", "", "exclusive collection end (RFC3339; default current time with --since)")
	fs.StringVar(&result.Store, "store", "", "archive SQLite path")
	fs.BoolVar(&result.RawLogs, "raw-logs", false, "retain exact logs in the <store>.raw sidecar (sensitive; opt-in)")
	fs.BoolVar(&result.Quiet, "quiet", false, "print only errors and final coverage")
	fs.BoolVar(&result.Verbose, "verbose", false, "print sanitized collection progress")
	fs.IntVar(&result.Concurrent, "concurrency", 4, "bounded repository collection concurrency (1-16)")
	fs.StringVar(&result.ImportFixture, "import-fixture", "", "import one explicitly synthetic offline snapshot (developer/test only)")
	if err := fs.Parse(args); err != nil {
		return result, err
	}
	if fs.NArg() != 0 || result.Store == "" {
		return result, fmt.Errorf("%w: archive accepts flags and requires --store", errUsage)
	}
	result.Targets.Repositories = append([]string(nil), repositories...)
	if result.ImportFixture != "" {
		if result.Targets.Organization != "" || len(result.Targets.Repositories) != 0 || from != "" || to != "" || since != "" || result.RawLogs {
			return result, fmt.Errorf("%w: --import-fixture cannot be combined with collection scope, time, or raw-log flags", errUsage)
		}
		return result, nil
	}
	if err := result.Targets.validate(); err != nil {
		return result, fmt.Errorf("%w: %v", errUsage, err)
	}
	if result.Concurrent < 1 || result.Concurrent > 16 || (result.Quiet && result.Verbose) {
		return result, fmt.Errorf("%w: invalid concurrency or logging flags", errUsage)
	}
	if since != "" {
		if from != "" {
			return result, fmt.Errorf("%w: --since and --from are mutually exclusive", errUsage)
		}
		var err error
		if result.Since, err = time.ParseDuration(since); err != nil || result.Since <= 0 || result.Since > 365*24*time.Hour {
			return result, fmt.Errorf("%w: --since must be a positive duration no greater than 8760h", errUsage)
		}
	} else if from == "" {
		return result, fmt.Errorf("%w: provide --since or --from", errUsage)
	}
	var err error
	if from != "" {
		parsed, parseErr := parseUTC(from)
		if parseErr != nil {
			return result, fmt.Errorf("%w: invalid --from: %v", errUsage, parseErr)
		}
		result.From = &parsed
	}
	if to != "" {
		result.To, err = parseUTC(to)
		if err != nil {
			return result, fmt.Errorf("%w: invalid --to: %v", errUsage, err)
		}
	} else if result.From != nil {
		return result, fmt.Errorf("%w: --to is required with --from", errUsage)
	}
	if result.From != nil && !result.From.Before(result.To) {
		return result, fmt.Errorf("%w: --from must precede --to", errUsage)
	}
	return result, nil
}

type replayOptions struct {
	Archive             string
	Incident            string
	Output              string
	RawLogs             bool
	FixedCollectionTime *time.Time
}

type demoOptions struct {
	Output string
}

const demoUsage = `Usage:
  cirewind demo --out CASE_DIR

Generates and verifies a deterministic synthetic case without credentials or
network access. The destination must not already exist. No raw logs are retained.
`

func parseDemo(args []string, output io.Writer) (demoOptions, error) {
	var result demoOptions
	// flag.FlagSet echoes the original command-line token on parse errors. Keep
	// that hostile text out of the terminal sink; only trusted help is forwarded,
	// while Run renders the returned error through the bounded sanitizer.
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	configureFlagHelp(fs, &flagOutput, demoUsage)
	fs.StringVar(&result.Output, "out", "", "new synthetic case output directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(output, &flagOutput)
			return result, err
		}
		return result, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() != 0 {
		return result, fmt.Errorf("%w: demo accepts flags only", errUsage)
	}
	if strings.TrimSpace(result.Output) == "" {
		return result, fmt.Errorf("%w: --out is required", errUsage)
	}
	return result, nil
}

const replayUsage = `Usage:
  cirewind replay --archive FILE --incident FILE --out CASE_DIR [--raw-logs]

Re-derives findings from compact archived facts without network access. A pack
requiring unarchived raw-log literals produces UNKNOWN_EVIDENCE_GAP. Raw
sidecar objects are copied into the new case only with --raw-logs.
`

func parseReplay(args []string, output io.Writer) (replayOptions, error) {
	var result replayOptions
	var fixed string
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	configureFlagHelp(fs, output, replayUsage)
	fs.StringVar(&result.Archive, "archive", "", "compact archive SQLite path")
	fs.StringVar(&result.Incident, "incident", "", "validated incident-pack YAML")
	fs.StringVar(&result.Output, "out", "", "new case output directory")
	fs.BoolVar(&result.RawLogs, "raw-logs", false, "copy retained archive raw logs into case raw/ (sensitive; opt-in)")
	fs.StringVar(&fixed, "fixed-collection-time", "", "deterministic RFC3339 analysis time (fixture/demo only)")
	if err := fs.Parse(args); err != nil {
		return result, err
	}
	if fs.NArg() != 0 || result.Archive == "" || result.Incident == "" || result.Output == "" {
		return result, fmt.Errorf("%w: --archive, --incident, and --out are required", errUsage)
	}
	if fixed != "" {
		parsed, err := parseUTC(fixed)
		if err != nil {
			return result, fmt.Errorf("%w: invalid --fixed-collection-time: %v", errUsage, err)
		}
		result.FixedCollectionTime = &parsed
	}
	return result, nil
}

func configureFlagHelp(fs *flag.FlagSet, output io.Writer, summary string) {
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprint(output, summary)
		fmt.Fprintln(output, "\nFlags:")
		fs.PrintDefaults()
	}
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.Location() != time.UTC {
		return time.Time{}, errors.New("timestamp must use the Z UTC offset")
	}
	return parsed.UTC(), nil
}
