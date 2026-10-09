# Command-line reference

```
svetovit -S <server> [options]
```

Svetovit walks `--target`, collects the CMS installs, extensions and lock files it finds, checks the host's OS
packages, sends everything to a [Rozhanitsy](https://github.com/TadeasDitte/rozhanitsy) server and prints the findings.
See [flow.md](flow.md) for the full pipeline and [support.md](support.md) for what is detected.

## Configuration sources

The server URL and token can come from, in order of precedence:

1. the `--server` / `--token` flags
2. the `ROZHANITSY_URL` / `SCAN_TOKEN` environment variables
3. a `.env` file in the working directory, which is loaded into the environment at startup (variables already set
   in the environment win)

## What to scan

### `-t, --target <dir>` (default `.`)

The directory to scan. It can be a single install (`/var/www/shop`) or a directory holding many installs, such as a
hosting server's tenant directories (`/var/www`, `/home`). Each install found is reported separately.

Point it at the web root rather than `/`: everything under the target is a candidate, and the walk is the expensive
part of a scan.

### `-d, --depth <n>` (default `-1`, unlimited)

How many directory levels below `--target` the walk descends. `0` looks at the target only, `1` also at its
immediate subdirectories, and so on.

Use it when you know the layout. On a host where every site lives at `/var/www/<site>/public_html`, `-d 2` finds all
of them without walking backups, logs or anything else lying around deeper. Depth limits where installs and lock
files are looked for; an install's plugins are always read, however deep they sit.

### `--mode small|half|full` (default `small`)

How much of an install is searched once it is found.

| Mode | Inside an install, Svetovit reads | Finds nested installs | Typical cost |
|---|---|---|---|
| `small` | the core version file, the extension directories named in the detector, and lock files in the install root and in those extension directories | no | lowest: core source trees, uploads and caches are never listed |
| `half` | everything, except the upload/cache directories listed under `skip:` in the detector (`wp-content/uploads`, `storage`, `sites/*/files`, ...) | yes | several times `small` |
| `full` | everything | yes, including ones hidden in upload directories | highest |

- **small** is right for routine scheduled scans: it reports the core, every plugin/module/theme and the
  dependencies they declare, at a fraction of the I/O.
- **half** adds installs nested inside other installs (a shop in `public_html/shop` under a WordPress
  `public_html`) and lock files anywhere in the install, such as one in a custom `tools/` directory.
- **full** also walks upload and cache directories. Legitimate software rarely lives there, but a forgotten or
  attacker-dropped copy of a CMS does. Use it for audits and incident response.

In every mode `vendor/`, `node_modules/` and `.git/` are skipped: the packages in them are already covered by the
`composer.lock` / `pnpm-lock.yaml` next to them.

### `--cross-filesystems`

By default the walk stays on the filesystem `--target` is on, like `find -xdev`. NFS shares, backup mounts and
bind mounts below the target are skipped, because they are often huge, slow, or a copy of what is already being
scanned. Pass this flag to follow them. (On Windows the check is not available and mounts are always followed.)

### `--skip-system`

Don't check the host's OS packages. Use it when scanning a mounted copy of another machine's web root, or in a
container whose OS is not the one you care about. See [support.md](support.md#operating-system-packages) for the
supported package managers.

## How fast to scan

### `-a, --aggressivity 1-5` (default `3`)

The scan is mostly directory listings and small file reads. On a cold cache each one is a random disk read, which
can hurt a busy server, especially on HDDs or shared storage. Aggressivity trades scan time for load:

| Level | Workers | Max filesystem operations per second | Use for |
|---|---|---|---|
| 1 | 1 | 100 | busy production hosts, shared SAN/NFS storage; runs slowly in the background |
| 2 | 2 | 500 | production hosts with some headroom |
| 3 | 4 | no limit | the default; fine for most servers |
| 4 | 8 | no limit | local SSDs |
| 5 | 16 | no limit | fast NVMe, or when the scan should finish as quickly as possible |

A filesystem operation is one directory listing, one version-file read or one lock-file parse. The limit is shared
by all workers, so level 1 never exceeds 100 operations a second however the work is split. As a rough guide, a
`small` scan of 200 WordPress sites with 8 plugins each is about 5,000 operations: under a second at level 3, about
10 seconds at level 2 and about 50 seconds at level 1.

Combine low levels with `ionice -c3 nice -n19` so the remaining I/O also yields to other processes.

### `--workers <n>`

Overrides the number of concurrent filesystem operations that `--aggressivity` picked, keeping its rate limit. For
example `-a 1 --workers 4` keeps the 100 ops/s cap but lets slow network storage serve four requests at a time.

## Server

### `-S, --server <url>` (env `ROZHANITSY_URL`, required)

Base URL of the Rozhanitsy instance, for example `https://rozhanitsy.tadesrv.eu` or your own.

### `-T, --token <token>` (env `SCAN_TOKEN`)

Optional bearer token. The public API needs none; set it only for an instance that requires one.

### `--timeout <duration>` (default `30s`)

Timeout of each HTTP request, in Go duration syntax (`45s`, `2m`). Components are sent in batches of 100, and
requests answered with 429, a 5xx or a network error are retried, so raise this only if single requests time out.

## What to report

### `-c, --confidence bounded|unbound|all` (default `all`)

- **bounded**: findings where the component's version falls inside a vulnerable range given by the advisory.
  These are the actionable ones.
- **unbound** (listed as "unmatched"): Svetovit could not confirm whether the component is affected, because an
  advisory names the product without affected versions, or because the name is shared by several vendors and the API
  refuses to guess.
- **all**: both.

Use `bounded` for alerting, where every line should need action; `all` for audits.

### `-m, --min-score <float>`

Only report vulnerabilities with a CVSS score of at least this value, e.g. `-m 7` for high and critical.

### `-s, --severity <list>`

Comma-separated CVSS severities to report: `critical`, `high`, `medium`, `low`. Use either this or `--min-score`,
whichever matches how your alerting is defined.

## Output

### `-f, --format normal|json|quiet` (default `normal`)

- **normal**: a human-readable report on stdout.
- **json**: the same data as JSON, for scripts and dashboards. OS packages are under the `system` key.
- **quiet**: nothing on stdout; only errors and warnings on stderr. Use it when only the exit code matters, or
  together with the `--o*` flags.

### `-l, --per-location`

Group the report by where each component was found (install root, extension directory, lock file), instead of one
list. Useful on multi-tenant hosts to see which site a finding belongs to.

### `--oN <file>`, `--oJ <file>`, `--oA <basename>`

Also write the report to files, independent of `--format`: `--oN` the normal report, `--oJ` JSON, `--oA` both, as
`<basename>.txt` and `<basename>.json`. For example `-f quiet --oA /var/log/svetovit/$(date +%F)` keeps a daily
record without printing anything.

## Tracking and notifications

### `--state[=<path>]` (env `SVETOVIT_STATE`)

Keep every finding in a SQLite database, so each run can report what changed since the previous one. The report
gets a "Since last scan" section (`changes` in JSON) with the counts of new, fixed and removed findings, the number
still open and the age of the oldest, plus a table of what was fixed or removed.

`--state` without a value uses `/var/lib/svetovit/state.db` when running as root, otherwise
`$XDG_STATE_HOME/svetovit/state.db` (`~/.local/state/...`; `%LocalAppData%\svetovit\state.db` on Windows). A path
must be given with `=`: `--state=/srv/svetovit.db`. The database is opened before the scan starts, so an unwritable
path fails straight away instead of after a long walk.

A finding is one advisory affecting one component version at one location (install root, plugin directory or lock
file). From one run to the next:

| Situation | Result |
|---|---|
| in this scan, not in the database (or resolved there) | **new** |
| in this scan and open in the database | still open; nothing is announced |
| missing from 2 consecutive scans of its location | **fixed** |
| its location below `--target` no longer exists, for 2 consecutive runs | **removed**: the site or plugin was deleted, not updated |
| its location was not scanned this run (another `--target`, an unreadable directory, a lock file that failed to parse, `--skip-system`), or it falls outside this run's `-m` / `-s` filters | left alone |

A run that fails (exit 1) never updates the database, so a failed API request cannot mark everything fixed. Two
scans running at the same time wait for each other.

### `--notify-url <url>` (env `SVETOVIT_NOTIFY_URL`)

Post findings to a chat webhook. The format follows the URL:

- `https://hooks.slack.com/...`: a Slack message
- `https://discord.com/api/webhooks/...`: a Discord message, kept under Discord's 2000-character limit
- anything else: JSON with a ready-made Markdown `text` (which Mattermost and Rocket.Chat incoming webhooks display
  as-is) and an `events` list (`type`, `location`, `component`, `version`, `advisory_id`, `severity`, `score`,
  `fixed_in`, `first_seen`, `days_open`) for your own tooling

With `--state`, only changes are posted: new findings once, then their resolution as fixed or removed. A run with no
changes posts nothing. If the webhook cannot be reached the scan still succeeds (with a warning) and the messages are
sent on the next run. Without `--state`, every run posts all current findings.

Long lists are cut with "…and N more"; the full list is in the report and in the generic payload's `events`.

### `--renotify <duration>`

With `--state`, post a "still vulnerable (N days)" reminder about critical and high findings that are still open
this long after they were last announced, e.g. `--renotify 7d` for a weekly reminder. Accepts days (`7d`) or Go
durations (`36h`). Off by default: a finding is announced once.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed, no known vulnerabilities found |
| 1 | the scan or the API request failed |
| 2 | invalid usage (bad flag or value, missing server URL) |
| 3 | scan completed and found known vulnerabilities |

## Recipes

```bash
# nightly cron job on a busy shared host: gentle, only actionable findings, kept on disk
ionice -c3 nice -n19 svetovit -a 1 -t /var/www -c bounded -f quiet --oA /var/log/svetovit/nightly

# incident response: everything, including installs hidden in upload directories
svetovit -t /var/www --mode full -a 5 -l

# hourly cron job posting only changes to Slack, with a weekly reminder about open critical/high findings
svetovit -t /var/www -c bounded -f quiet --state --notify-url "$SLACK_WEBHOOK" --renotify 7d

# one site, high and critical only, as JSON
svetovit -t /var/www/shop -s critical,high -f json --skip-system
```
