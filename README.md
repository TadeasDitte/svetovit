# Svetovit

Svetovit scans a server for installed software and checks it against known vulnerabilities. It is the official
command-line client for [Rozhanitsy](https://github.com/TadeasDitte/rozhanitsy), the vulnerability lookup API.

It looks for:

- **CMS installs**: WordPress, Drupal, Joomla, Laravel and PrestaShop, including their plugins, modules and themes.
- **Dependency lock files**: every `composer.lock` and `pnpm-lock.yaml` it finds.
- **Host OS packages**: Debian/Ubuntu (dpkg), RHEL-likes and SUSE (rpm), Alpine (apk), Arch (pacman), NixOS and FreeBSD (pkg).

Everything found is sent to Rozhanitsy, and the findings are printed as a report or JSON.
See [docs/flow.md](docs/flow.md) for how a scan works from start to finish.

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
  -c, --confidence string   which results to report: bounded (known-vulnerable), unbound (unmatched), or all (default "all")
  -d, --depth int           max directory levels below --target to search for CMS installs (0 = target only,
                            1 = target's immediate subdirectories, ...); default is a full recursive search (default -1)
  -f, --format string       format output as json or quiet. quiet shows only errors (default "normal")
  -m, --min-score float     only report vulnerabilities with CVSS score >= this value
      --oA string           also write the report to <basename>.txt and <basename>.json
      --oJ string           also write a JSON report to this file
      --oN string           also write the normal-format report to this file
  -l, --per-location        show report per location
  -S, --server string       Rozhanitsy server base URL (env ROZHANITSY_URL)
  -s, --severity string     comma-separated CVSS severities to report, e.g. critical,high
      --skip-system         don't check the host's OS packages (dpkg, rpm, apk, pacman, nix, FreeBSD pkg)
  -t, --target string       path to the directory to scan (default ".")
      --timeout duration    HTTP request timeout (default 30s)
      --workers int         max concurrent filesystem operations while scanning (0 = automatic)
  -T, --token string        optional Rozhanitsy bearer token (env SCAN_TOKEN); the API is public
```

## How scanning works

- `--target` can be a single install or a directory holding many (for example a hosting server's tenant directories).
  Svetovit walks it up to `--depth` levels and reports each install separately; use `--per-location` to see the
  results grouped by install.
- `vendor/`, `node_modules/` and `.git/` are never searched.
- Host OS packages are checked in a separate request and reported in their own "System packages" block (the `system`
  key in JSON output). Use `--skip-system` to leave them out.
- Results fall into two groups, selectable with `--confidence`:
  - **bounded**: the component's version falls inside a vulnerable range given by the advisory.
  - **unbound** (listed as "unmatched"): Svetovit could not confirm whether the component is affected, either because
    an advisory names the product but gives no affected versions, or because the product name is shared by several
    vendors and the API refuses to guess.

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
