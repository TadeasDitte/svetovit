# What Svetovit supports

Svetovit reports three kinds of components: CMS installs with their extensions, dependencies from lock files, and the
host's OS packages. Everything is checked against [Rozhanitsy](https://github.com/TadeasDitte/rozhanitsy).

## CMS and frameworks

Each CMS is described by a YAML [detector](../detectors/). An install is recognised by a marker file. Its core version
is read from a file in the install, and each extension's version from a file inside the extension's directory.

| CMS | Recognised by | Core version from | Extensions scanned |
|---|---|---|---|
| WordPress | `wp-load.php` or `wp-includes/version.php` | `$wp_version` in `wp-includes/version.php` | plugins (`wp-content/plugins/*`), themes (`wp-content/themes/*`) |
| Drupal 8+ | `core/lib/Drupal.php` | `const VERSION` in `core/lib/Drupal.php` | modules and themes (`modules/*`, `modules/*/*`, `themes/*`, `themes/*/*`, which covers `contrib/` and `custom/`) |
| Joomla | `administrator/manifests/files/joomla.xml` | `<version>` in that manifest | plugins (`plugins/*/*`), components (`administrator/components/*`), site and admin modules (`modules/*`, `administrator/modules/*`), site templates (`templates/*`) |
| PrestaShop | `config/settings.inc.php` | `_PS_VERSION_` in `config/settings.inc.php`, else `const VERSION` in `app/AppKernel.php` (1.7+) | modules (`modules/*`), themes (`themes/*`) |
| Laravel | `artisan` or `vendor/laravel/framework/.../Application.php` | `const VERSION` in `vendor/laravel/framework/src/Illuminate/Foundation/Application.php` | none: an app's packages come from its `composer.lock` |

### Where extension versions come from

| CMS | Extension | Version source |
|---|---|---|
| WordPress | plugin | the `Version:` line of the PHP file that carries the `Plugin Name:` header (`<slug>.php` is tried first), else `Stable tag:` in `readme.txt` |
| WordPress | theme | `Version:` in `style.css` |
| Drupal | module, theme | `version:` in `*.info.yml` (`<name>.info.yml` first). Accepts `1.2.3`, `8.x-1.0` and `1.0.x-dev` |
| Joomla | plugin, component, module | `<version>` in the extension's XML manifest (`<name>.xml` first) |
| Joomla | template | `<version>` in `templateDetails.xml` |
| PrestaShop | module | `<version>` in `config.xml` |
| PrestaShop | theme | `version:` in `config/theme.yml` |

An extension directory without a readable version is not reported. Extensions are sent under their directory name
and the CMS they plug into. The API only counts a finding for an extension when the advisory names that same CMS,
so a plugin called `gallery` is not matched against every other product called `gallery`.

### Directories skipped inside installs

With `--mode half`, the walk enters installs but leaves out their upload and cache directories. `--mode small`
never walks them anyway, and `--mode full` walks them too.

| CMS | Skipped |
|---|---|
| WordPress | `wp-content/uploads`, `wp-content/cache` |
| Drupal | `sites/*/files` |
| Joomla | `images`, `cache`, `tmp`, `administrator/cache` |
| PrestaShop | `var/cache`, `cache`, `img` |
| Laravel | `storage` |

### Not supported

- Drupal 7 and older (no `core/lib/Drupal.php`; modules under `sites/all/modules`).
- WordPress must-use plugins (`wp-content/mu-plugins`) and drop-ins (`wp-content/*.php`).
- Other CMSes (Magento, TYPO3, Craft, ...) have no detector yet. See [adding a CMS](#adding-a-cms).

## Lock files

Lock files are found while walking the target. In `--mode small` they are also found in an install's root and in
each extension's directory. `vendor/` and `node_modules/` are never searched.

| File | Package manager | Ecosystem | Notes |
|---|---|---|---|
| `composer.lock` | Composer (PHP) | Packagist | `packages` and `packages-dev`; branch versions such as `dev-main` are skipped |
| `pnpm-lock.yaml` | pnpm (JavaScript) | npm | lockfile v5 (`/name/1.0.0` keys) and v6+ (`name@1.0.0` keys); peer-dependency suffixes are stripped |

Not supported yet: `package-lock.json` (npm), `yarn.lock`, `bun.lockb`, `Gemfile.lock`, `poetry.lock` and
`requirements.txt`, `go.sum`, `Cargo.lock`.

## Operating system packages

On Linux, the distribution is read from `/etc/os-release` (or `/usr/lib/os-release`). The package manager is chosen
from `ID`, falling back to `ID_LIKE`, so derivatives such as Linux Mint or Pop!_OS are handled through their parent
distribution. The ecosystem tells the API which advisory database the versions belong to.

| Distribution | Package manager | Read from | Ecosystem sent |
|---|---|---|---|
| Debian | dpkg | `/var/lib/dpkg/status` | `Debian:<major>` |
| Ubuntu | dpkg | `/var/lib/dpkg/status` | `Ubuntu:<version>`, plus `:LTS` for even-year `.04` releases |
| RHEL | rpm | `rpm -qa` | `Red Hat` |
| Rocky Linux | rpm | `rpm -qa` | `Rocky Linux:<major>` |
| AlmaLinux | rpm | `rpm -qa` | `AlmaLinux:<major>` |
| Fedora, CentOS, Oracle Linux, Amazon Linux, SUSE / openSUSE | rpm | `rpm -qa` | `<ID>:<VERSION_ID>` |
| Alpine | apk | `/lib/apk/db/installed` | `Alpine:v<major>.<minor>` |
| Arch Linux | pacman | `/var/lib/pacman/local` | `Arch Linux` |
| NixOS | nix | `nix-store -q --requisites /run/current-system` | none (NVD only, see below) |
| FreeBSD | pkg | `pkg query` | `FreeBSD` |

Notes:

- **dpkg** packages are reported under their source package name and version (e.g. `openssl`, not `libssl3`),
  which is how Debian and Ubuntu advisories are keyed.
- **apk** packages are reported under their origin package for the same reason.
- **rpm** epochs of `0` are dropped from versions.
- **Derivatives** use the parent's package manager, but the ecosystem is built from their own `ID`. One whose
  advisories are not published under that ID gets fewer matches.
- **NixOS** has no advisory ecosystem, so packages are matched against NVD by name. Every package that comes back
  flagged or ambiguous is re-checked under the exact vendor/product CPE that nixpkgs records for it, which removes
  unrelated name clashes. This needs `nix` with flakes enabled. Without it, the name-only results are kept.
- Other systems, including macOS and Windows, are skipped with a notice. `--skip-system` turns the check off.

## Platforms

| | Linux | macOS | Windows | FreeBSD |
|---|---|---|---|---|
| Release binaries (amd64, arm64) | yes | yes | yes | no: `go install` |
| CMS and lock-file scanning | yes | yes | yes | yes |
| OS package check | yes | no | no | yes |
| Stay on one filesystem (default unless `--cross-filesystems`) | yes | yes | no: mounts are followed | yes |

## Adding a CMS

Drop a YAML file into [`detectors/`](../detectors). It is embedded at build time and picked up automatically.

```yaml
name: mycms                  # sent as the vendor and product of the core
markers:                     # any one present means "this directory is an install"
  - lib/MyCms.php
version:                     # tried in order; the first capture group is the version
  - file: lib/MyCms.php
    regex: 'VERSION\s*=\s*''([^'']+)'''
plugins:                     # optional
  - glob: "extensions/*"     # directories, relative to the install root
    version:
      - file: "*.json"       # a glob tries <dir name>.json first
        regex: '"version":\s*"([^"]+)"'
skip:                        # optional: dirs --mode half does not enter
  - uploads
```

Prefer markers directly in the install root: they are recognised from the directory listing alone, with no extra
disk reads. Only the first 64 KiB of a version file is searched.
