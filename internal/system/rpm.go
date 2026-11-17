package system

import (
	"strconv"
	"strings"
)

// ForeignRPM reports that the installed package cannot be the distro build the advisory is about:
// its epoch is below the advisory's, so rpm counts it as older for ever, yet its version is already
// at or past the one named as fixed. A distro build never looks like that, and no later build of the
// local package can clear the advisory either, so the match is not evidence of a missing patch.
func ForeignRPM(installed, fixedIn string) bool {
	if installed == "" || fixedIn == "" {
		return false
	}
	installedEpoch, installedVR := splitEVR(installed)
	fixedEpoch, fixedVR := splitEVR(fixedIn)
	return installedEpoch < fixedEpoch && rpmvercmp(installedVR, fixedVR) >= 0
}

func splitEVR(evr string) (int, string) {
	if epoch, rest, ok := strings.Cut(strings.TrimSpace(evr), ":"); ok {
		if n, err := strconv.Atoi(epoch); err == nil && n >= 0 {
			return n, rest
		}
	}
	return 0, strings.TrimSpace(evr)
}

// rpmvercmp follows rpm's own lib/rpmvercmp.c: segments of digits and of letters are compared in
// turn, a digit segment outranks a letter one, '~' sorts before everything and '^' before the end
// of the string.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		if at(a, i) == '~' || at(b, j) == '~' {
			switch {
			case at(a, i) != '~':
				return 1
			case at(b, j) != '~':
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if at(a, i) == '^' || at(b, j) == '^' {
			switch {
			case i == len(a):
				return -1
			case j == len(b):
				return 1
			case a[i] != '^':
				return 1
			case b[j] != '^':
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i == len(a) || j == len(b) {
			break
		}

		startA, startB := i, j
		numeric := isDigit(a[i])
		inSegment := isAlpha
		if numeric {
			inSegment = isDigit
		}
		for i < len(a) && inSegment(a[i]) {
			i++
		}
		for j < len(b) && inSegment(b[j]) {
			j++
		}

		segA, segB := a[startA:i], b[startB:j]
		if segB == "" {
			// One side starts a digit segment where the other starts letters: digits win.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			segA, segB = strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				return newerIf(len(segA) > len(segB))
			}
		}
		if segA != segB {
			return newerIf(segA > segB)
		}
	}

	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func at(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func newerIf(greater bool) int {
	if greater {
		return 1
	}
	return -1
}
