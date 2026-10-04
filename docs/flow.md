# Svetovit flow

End to end, from a directory on disk to a report. The API side is described in the
[Rozhanitsy wiki](https://github.com/TadeasDitte/rozhanitsy/wiki/API).

```mermaid
flowchart TD
    A[svetovit --target DIR] --> B[scanner.walk<br/>find CMS installs + lock files<br/>skips vendor/, node_modules/, .git/]
    B --> C{CMS marker found?}
    C -->|yes| D[detector: core version<br/>Component vendor=cms, product=cms]
    D --> E[detector: extensions<br/>Component product=dir name, no vendor<br/>Platform=cms]
    C -->|lock file| F[lockfile parser<br/>composer.lock / pnpm-lock.yaml<br/>Component + ecosystem Packagist / npm]
    A --> G[system.Detect<br/>dpkg, rpm, apk, pacman, nix, pkg<br/>Component + distro ecosystem]

    D --> H
    E --> H
    F --> H
    G --> H

    H[rozhanitsy.CheckVulns<br/>dedupe identical components<br/>batches of 100] --> I[POST /api/v1/check/batch<br/>retry on 429]
    I --> J{per result}

    J -->|ambiguous: true| K{CMS extension?}
    K -->|no| U[Unmatched, tagged ambiguous]
    K -->|yes| L[re-check once per candidate vendor<br/>keep only findings where<br/>affected_range.plugs_into == Platform]
    L --> V

    J -->|vulnerabilities| M{filters}
    M -->|extension without vendor| N[require plugs_into == Platform]
    M -->|OS pkg without ecosystem| O[NVD only]
    M -->|confidence low| U
    M -->|min score / severity| P[drop]
    N --> V
    O --> V
    M --> V[Vulnerable<br/>vendor from affected_range.vendor<br/>fixed_in]

    G -. nix only .-> Q[system.NixCPEs<br/>re-check flagged + ambiguous names<br/>under the exact nixpkgs vendor/product]
    Q --> H

    V --> R[report.Print / WriteJSON<br/>per location optional]
    U --> R
    R --> S[exit 0 clean, 3 findings, 1 error, 2 usage]
```

## Decisions worth knowing

| Situation | Behavior | Why |
|---|---|---|
| API answers `ambiguous: true` | CMS extensions are retried per candidate vendor, everything else is reported as unmatched | the API refuses to guess, a bare OS package name could belong to unrelated software |
| Extension has no vendor | a finding only counts when `plugs_into` equals the CMS | a dir name like `gallery` or `cache` otherwise matches every vendor and ecosystem that ships one |
| Vendor of a finding | `affected_range.vendor` from the check response | no extra `/vulnerabilities/{id}` lookups, which count against 60 requests/minute |
| 429 | retried, honoring `Retry-After` (max 5) | the API is throttled |
| WordPress plugin version | read from the file with a `Plugin Name:` header | a bundled library's `Version:` line in another file is not the plugin's version |
