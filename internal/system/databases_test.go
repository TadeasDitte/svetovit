package system

import (
	"reflect"
	"testing"
)

func TestParseNixClosure(t *testing.T) {
	const h = "/nix/store/3ppjkfrmkr0s0c74hs4ddmld3c9cqkzr-"
	in := h + "libidn2-2.3.8\n" +
		h + "glibc-2.44-25\n" +
		h + "xgcc-16.2.0-libgcc\n" +
		h + "python3.13-requests-2.32.3\n" +
		h + "openssl-3.0.14-bin\n" +
		h + "openssl-3.0.14\n" + // same package, another output: deduped
		h + "iana-etc-20251215\n" +
		h + "foo-1.0.drv\n" +
		h + "etc\n" +
		h + "nixos-system-host-26.11.20260101\n" +
		h + "stdenv-linux-source\n"

	want := []Package{
		{"libidn2", "2.3.8"},
		{"glibc", "2.44"},
		{"xgcc", "16.2.0"},
		{"python3.13-requests", "2.32.3"},
		{"openssl", "3.0.14"},
		{"iana-etc", "20251215"},
	}
	if got := parseNixClosure(in); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNixOSDetection(t *testing.T) {
	if managerFor([]string{"nixos"}) != Nix {
		t.Error("nixos should map to the Nix manager")
	}
	if ecosystemFor("nixos", "26.11") != "" {
		t.Error("nixos has no OSV ecosystem")
	}
}
