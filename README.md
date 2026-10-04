# Svetovit

The official implementation of [Rozhanitsy](https://github.com/TadeasDitte/Rozhanitsy)

## Usage

Point Svetovit at a [Rozhanitsy](https://rozhanitsy.tadesrv.eu) instance (or your self hosted one). The API is public, so a token is optional.
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
  -S, --server string       Rozhanitsy server base URL (env ROZHANITSY_URL)
  -s, --severity string     comma-separated CVSS severities to report, e.g. critical,high
      --skip-system         don't check the host's OS packages (dpkg, rpm, apk, pacman, nix, FreeBSD pkg)
  -t, --target string       path to the directory to scan (default ".")
      --timeout duration    HTTP request timeout (default 30s)
      --workers int         max concurrent filesystem operations while scanning (0 = automatic)
  -T, --token string        optional Rozhanitsy bearer token (env SCAN_TOKEN); the API is public
```
```
```

Besides the CMS installs matched by the detectors, Svetovit also reads every `composer.lock` and `pnpm-lock.yaml`
under `--target` (within `--depth`, skipping `vendor/` and `node_modules/`).

On Debian/Ubuntu, RHEL-likes/SUSE, Alpine, Arch, NixOS and FreeBSD hosts the installed OS packages are checked too, in separate
requests, and reported in their own "System packages" block (`system` key in JSON output).

Minimal command example:
`svetovit -S ${ROZHANITSY_URL}`

## Contributing

Expanding detector configs and any other form of contribution is appreciated
