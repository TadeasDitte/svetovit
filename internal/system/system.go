// Package system detects the host operating system and lists the packages installed by its package manager.
package system

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrUnsupported is returned by Detect when the host has no package manager Svetovit knows how to read.
var ErrUnsupported = errors.New("unsupported operating system")

type Manager string

const (
	Dpkg   Manager = "dpkg"
	RPM    Manager = "rpm"
	APK    Manager = "apk"
	Pacman Manager = "pacman"
	BSDPkg Manager = "pkg"
)

// Environment describes the host OS. Ecosystem follows the OSV ecosystem naming (e.g. "Debian:12").
type Environment struct {
	ID        string
	VersionID string
	Name      string
	Ecosystem string
	Manager   Manager
}

type Package struct {
	Name    string
	Version string
}

// Detect identifies the host OS and its package manager.
func Detect() (*Environment, error) {
	if runtime.GOOS == "freebsd" {
		return &Environment{ID: "freebsd", Name: "FreeBSD", Ecosystem: "FreeBSD", Manager: BSDPkg}, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, runtime.GOOS)
	}

	release, err := readOSRelease()
	if err != nil {
		return nil, err
	}

	env := &Environment{
		ID:        release["ID"],
		VersionID: release["VERSION_ID"],
		Name:      release["PRETTY_NAME"],
	}
	if env.Name == "" {
		env.Name = release["NAME"]
	}

	families := append([]string{env.ID}, strings.Fields(release["ID_LIKE"])...)
	env.Manager = managerFor(families)
	if env.Manager == "" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, env.Name)
	}
	env.Ecosystem = ecosystemFor(env.ID, env.VersionID)

	return env, nil
}

func readOSRelease() (map[string]string, error) {
	var lastErr error
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		defer f.Close()

		values := make(map[string]string)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(key, "#") {
				continue
			}
			values[key] = strings.Trim(value, `"'`)
		}
		return values, sc.Err()
	}
	return nil, fmt.Errorf("%w: reading os-release: %v", ErrUnsupported, lastErr)
}

func managerFor(families []string) Manager {
	for _, id := range families {
		switch id {
		case "debian", "ubuntu":
			return Dpkg
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn", "suse", "sles", "opensuse":
			return RPM
		case "alpine":
			return APK
		case "arch":
			return Pacman
		}
		if strings.HasPrefix(id, "opensuse") {
			return RPM
		}
	}
	return ""
}

// ecosystemFor maps os-release ID/VERSION_ID to the OSV ecosystem name, falling back to "ID:VERSION_ID".
func ecosystemFor(id, versionID string) string {
	major, _, _ := strings.Cut(versionID, ".")
	switch id {
	case "debian":
		return "Debian:" + major
	case "ubuntu":
		// LTS releases are the even-year .04 ones.
		year, month, _ := strings.Cut(versionID, ".")
		if month == "04" && len(year) == 2 && (year[1]-'0')%2 == 0 {
			return "Ubuntu:" + versionID + ":LTS"
		}
		return "Ubuntu:" + versionID
	case "alpine":
		parts := strings.SplitN(versionID, ".", 3)
		return "Alpine:v" + strings.Join(parts[:min(2, len(parts))], ".")
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "rhel":
		return "Red Hat"
	case "arch":
		return "Arch Linux"
	}
	if versionID == "" {
		return id
	}
	return id + ":" + versionID
}

const (
	dpkgStatus    = "/var/lib/dpkg/status"
	apkInstalled  = "/lib/apk/db/installed"
	pacmanLocalDB = "/var/lib/pacman/local"
)

// Source names where the package list is read from, used as the report location.
func (e *Environment) Source() string {
	switch e.Manager {
	case Dpkg:
		return dpkgStatus
	case APK:
		return apkInstalled
	case Pacman:
		return pacmanLocalDB
	}
	return string(e.Manager)
}

// Packages lists the packages installed on the host.
func (e *Environment) Packages() ([]Package, error) {
	switch e.Manager {
	case Dpkg:
		return parseDpkgStatus(dpkgStatus)
	case APK:
		return parseAPKInstalled(apkInstalled)
	case Pacman:
		return parsePacmanLocal(pacmanLocalDB)
	case RPM:
		return queryTabSeparated("rpm", "-qa", "--qf", `%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n`)
	case BSDPkg:
		return queryTabSeparated("pkg", "query", `%n\t%v`)
	}
	return nil, fmt.Errorf("%w: no package manager", ErrUnsupported)
}

func queryTabSeparated(name string, args ...string) ([]Package, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("running %s: %w", name, err)
	}

	var packages []Package
	for _, line := range strings.Split(string(out), "\n") {
		pkgName, version, ok := strings.Cut(line, "\t")
		if !ok || pkgName == "" || version == "" {
			continue
		}
		// rpm reports a zero epoch for packages that have none; OSV omits it.
		version = strings.TrimPrefix(version, "0:")
		packages = append(packages, Package{Name: pkgName, Version: version})
	}
	return packages, nil
}
