# Svetovit

The official implementation of [Rozhanitsy](https://github.com/TadeasDitte/Rozhanitsy)

## Usage

Log in to [Rozhanitsy](https://rozhanitsy.tadesrv.eu) (or your self hosted instance) and generate an API token
Download the [static binary](https://github.com/TadeasDitte/Svetovit/releases/latest) from the latest build

```bash
Usage of svetovit:
  -c, --confidence string   which results to report: bounded (known-vulnerable), unbound (unmatched), or all (default "all")
  -d, --depth int           max directory levels below --target to search for CMS installs (0 = target only, 1 = target's immediate subdirectories, ...); default is a full recursive search (default -1)
  -f, --format string       format output as json or quiet. quiet shows only errors (default "normal")
  -m, --min-score float     only report vulnerabilities with CVSS score >= this value
      --oA string           also write the report to <basename>.txt and <basename>.json
      --oJ string           also write a JSON report to this file
      --oN string           also write the normal-format report to this file
  -l, --per-location        show report per location
  -s, --server string       Rozhanitsy server base URL (env ROZHANITSY_URL)
      --severity string     comma-separated CVSS severities to report, e.g. critical,high
      --skip-system         don't check the host's OS packages (dpkg, rpm, apk, pacman, FreeBSD pkg)
  -t, --target string       path to the directory to scan (default ".")
      --timeout duration    HTTP request timeout (default 30s)
      --token string        Rozhanitsy scan host bearer token (env SCAN_TOKEN)
```
```
```

Besides the CMS installs matched by the detectors, Svetovit also reads every `composer.lock` and `pnpm-lock.yaml`
under `--target` (within `--depth`, skipping `vendor/` and `node_modules/`).

On Debian/Ubuntu, RHEL-likes/SUSE, Alpine, Arch and FreeBSD hosts the installed OS packages are checked too, in a
separate request, and reported in their own "System packages" block (`system` key in JSON output).

Minimal command example:
`svetovit --token ${API_TOKEN} -s ${ROZHANITSY_URL}`

## Contributing

Expanding detector configs and any other form of contribution is appreciated
