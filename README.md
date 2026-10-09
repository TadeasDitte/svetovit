# Svetovit

Svetovit scans a server for installed software and checks it against known vulnerabilities. It is the official
command-line client for [Rozhanitsy](https://github.com/TadeasDitte/rozhanitsy), the vulnerability lookup API.

It looks for:

- **CMS installs**: WordPress, Drupal, Joomla, Laravel and PrestaShop, including their plugins, modules and themes.
- **Dependency lock files**: every `composer.lock` and `pnpm-lock.yaml` it finds.
- **Host OS packages**: Debian/Ubuntu (dpkg), RHEL-likes and SUSE (rpm), Alpine (apk), Arch (pacman), NixOS and FreeBSD (pkg).

Everything found is sent to Rozhanitsy, and the findings are printed as a report or JSON.
See [docs/flow.md](docs/flow.md) for how a scan works from start to finish, [docs/CLI.md](docs/CLI.md) for every
option and when to use it, and [docs/support.md](docs/support.md) for the supported CMSes, lock files and OS package
managers.

## Installation

Download the static binary for your platform from the
[latest release](https://github.com/TadeasDitte/Svetovit/releases/latest). Builds are published for Linux, macOS and
Windows on amd64 and arm64.

Or install it with Go:

```bash
go install github.com/TadeasDitte/Svetovit/cmd/svetovit@latest
```

## Quick start

Point Svetovit at a [Rozhanitsy](https://rozhanitsy.tadesrv.eu) instance (the public one or your own). The API is
public, so a token is optional.

```bash
# scan the current directory and the host's OS packages
svetovit -S https://rozhanitsy.tadesrv.eu

# scan a web root, only report critical and high findings
svetovit -S "$ROZHANITSY_URL" -t /var/www -s critical,high

# machine-readable output, saved alongside as report.txt and report.json
svetovit -S "$ROZHANITSY_URL" -t /var/www -f json --oA report
```

The server and token can also come from the environment (`ROZHANITSY_URL`, `SCAN_TOKEN`) or from a `.env` file in the
working directory.

## Options

```
  -a, --aggressivity int    scan speed, 1 (gentlest) to 5 (fastest): 1 = 1 worker at <=100 fs ops/s, 2 = 2 workers at
                            <=500 ops/s, 3 = 4 workers, 4 = 8, 5 = 16 (default 3)
      --cross-filesystems   descend into directories mounted from other filesystems (NFS, backup mounts, ...) below --target
  -c, --confidence string   which results to report: bounded (known-vulnerable), unbound (unmatched), or all (default "all")
  -d, --depth int           max directory levels below --target to search for CMS installs (0 = target only,
                            1 = target's immediate subdirectories, ...); default is a full recursive search (default -1)
  -f, --format string       format output as json or quiet. quiet shows only errors (default "normal")
  -m, --min-score float     only report vulnerabilities with CVSS score >= this value
      --mode string         how much of an install to search: small (plugins and their lock files only), half
                            (everything inside installs, including nested installs, except upload/cache dirs),
                            full (everything) (default "small")
      --notify-url string   post findings to this webhook (env SVETOVIT_NOTIFY_URL): Slack, Discord, or generic JSON;
                            with --state only changes are posted
      --oA string           also write the report to <basename>.txt and <basename>.json
      --oJ string           also write a JSON report to this file
      --oN string           also write the normal-format report to this file
  -l, --per-location        show report per location
      --renotify string     with --state, remind about critical and high findings still open this long after the last
                            message, e.g. 7d or 12h
  -S, --server string       Rozhanitsy server base URL (env ROZHANITSY_URL)
  -s, --severity string     comma-separated CVSS severities to report, e.g. critical,high
      --skip-system         don't check the host's OS packages (dpkg, rpm, apk, pacman, nix, FreeBSD pkg)
      --state[="default"]   keep findings in a SQLite database at this path (env SVETOVIT_STATE) to report what is new,
                            fixed or still open; --state alone uses /var/lib/svetovit/state.db as root, else
                            ~/.local/state/svetovit/state.db
  -t, --target string       path to the directory to scan (default ".")
      --timeout duration    HTTP request timeout (default 30s)
      --workers int         override the number of concurrent filesystem operations set by --aggressivity
  -T, --token string        optional Rozhanitsy bearer token (env SCAN_TOKEN); the API is public
```

## How scanning works

- `--target` can be a single install or a directory holding many (for example a hosting server's tenant directories).
  Svetovit walks it up to `--depth` levels and reports each install separately; use `--per-location` to see the
  results grouped by install.
- `vendor/`, `node_modules/` and `.git/` are never searched; their packages come from the lock files.
- `--mode` sets how much of an install is searched once it is found:
  - **small** (default): the walk stops at the install's root. Below it, only the plugin, module and theme
    directories named in its [detector](detectors/) are read, plus the lock files in the install root and in those
    directories. Uploads, caches and core source trees are never listed, and an install nested inside another is
    not found.
  - **half**: the walk continues inside installs, so nested installs and lock files anywhere in them are found, but
    the upload and cache directories listed under `skip:` in each detector (for example `wp-content/uploads`, Drupal
    `sites/*/files`, Laravel `storage`) are left out.
  - **full**: everything below `--target` is walked, including those upload and cache directories, which is where a
    dropped copy of a CMS would hide. Expect several times the I/O of `small`.
- The walk stays on the filesystem `--target` is on, like `find -xdev`; pass `--cross-filesystems` to follow mounts.
- Host OS packages are checked in a separate request and reported in their own "System packages" block (the `system`
  key in JSON output). Use `--skip-system` to leave them out.
- Results fall into two groups, selectable with `--confidence`:
  - **bounded**: the component's version falls inside a vulnerable range given by the advisory.
  - **unbound** (listed as "unmatched"): Svetovit could not confirm whether the component is affected, either because
    an advisory names the product but gives no affected versions, or because the product name is shared by several
    vendors and the API refuses to guess.

## Running across a fleet

The walk is mostly directory listings, and on a cold cache each one is a random disk read. When running Svetovit
from Ansible or cron on many hosts:

- point `--target` at the web root (e.g. `/var/www`), not `/`
- run it at idle I/O priority: `ionice -c3 nice -n19 svetovit ...`
- keep `--aggressivity` at 3 or below on HDDs and network or shared storage; `-a 1` or `-a 2` caps the scan at
  100 or 500 filesystem operations per second, so it can run slowly in the background on a busy host
- if hosts share a datastore or SAN, limit how many scan at once (Ansible `serial:` or a low `forks`)

## Tracking changes and notifications

With `--state`, Svetovit keeps its findings in a SQLite database and the report ends with what changed since the
last run: new findings, fixed ones, removed ones (the site or plugin was deleted) and how long the rest have been
open. A finding counts as fixed only after two consecutive scans of its location miss it, and a failed run never
touches the database. `--notify-url` posts these changes to Slack, Discord or any JSON webhook, once each;
`--renotify 7d` adds a weekly reminder about critical and high findings that are still open. See
[docs/CLI.md](docs/CLI.md#tracking-and-notifications).

```bash
# hourly from cron: post only what changed
svetovit -t /var/www -c bounded -f quiet --state --notify-url "$SLACK_WEBHOOK" --renotify 7d
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed, no known vulnerabilities found |
| 1 | the scan or the API request failed |
| 2 | invalid usage (bad flag, missing server URL) |
| 3 | scan completed and found known vulnerabilities |


## Contributing

Contributions are welcome. The easiest way to help is to add or improve a detector: each supported CMS is described
by a small YAML file in [`detectors/`](detectors) (markers that identify an install, plus where to read the core and
extension versions from). Drop in a new file and it is picked up automatically.

```bash
go test ./...
```

## Contributors

<a href="https://github.com/TadeasDitte" title="TadeasDitte">
  <img src="https://github.com/TadeasDitte.png?size=100" width="50" height="50" alt="TadeasDitte">
</a>
<a href="https://github.com/shad0wRoot" title="shad0wRoot">
  <img src="https://github.com/shad0wRoot.png?size=100" width="50" height="50" alt="shad0wRoot">
</a>
