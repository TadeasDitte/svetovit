package system

import "testing"

func TestRPMVerCmp(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.26.3", "1.31.8", -1},
		{"1.31.8", "1.26.3", 1},
		{"2.0.1", "2.0.1a", -1},
		{"2.0.1a", "2.0.1", 1},
		{"1.0", "1.0.1", -1},
		{"5.5p1", "5.5p2", -1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"1.0010", "1.9", 1},
		{"1.0001", "1.1", 0}, // rpm strips leading zeros before comparing digit runs
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0", 1},
		{"1.0-", "1.0", 0},
		{"a", "1", -1},
		{"1", "a", 1},
		{"b", "a", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^", "1.0^", 0},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git1", "1.01", -1},
		{"1.26.3-6.el10_2.4", "1.26.3-16.el10_3.1", -1},
		{"1.31.8-.el10", "1.26.3-16.el10_3.1", 1},
	}
	for _, tt := range tests {
		if got := rpmvercmp(tt.a, tt.b); got != tt.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSplitEVR(t *testing.T) {
	tests := []struct {
		evr     string
		epoch   int
		version string
	}{
		{"1.31.8-.el10", 0, "1.31.8-.el10"},
		{"0:1.2-3", 0, "1.2-3"},
		{"2:1.26.3-16.el10_3.1", 2, "1.26.3-16.el10_3.1"},
		{"10:1.0", 10, "1.0"},
		{"1.2:3", 0, "1.2:3"},
		{"-1:1.0", 0, "-1:1.0"},
		{"", 0, ""},
	}
	for _, tt := range tests {
		epoch, version := splitEVR(tt.evr)
		if epoch != tt.epoch || version != tt.version {
			t.Errorf("splitEVR(%q) = %d, %q; want %d, %q", tt.evr, epoch, version, tt.epoch, tt.version)
		}
	}
}

func TestForeignRPM(t *testing.T) {
	tests := []struct {
		name               string
		installed, fixedIn string
		want               bool
	}{
		{"self-built nginx against Rocky errata", "1.31.8-.el10", "2:1.26.3-16.el10_3.1", true},
		{"local rebuild of the fixed source", "1.26.3-16.el10_3.1", "2:1.26.3-16.el10_3.1", true},
		{"distro build genuinely behind the fix", "2:1.26.3-6.el10_2.4", "2:1.26.3-16.el10_3.1", false},
		{"no epoch on either side", "1.26.3-6.el10_2.4", "1.26.3-16.el10_3.1", false},
		{"explicit zero epoch on both sides", "0:1.26.3-6", "0:1.26.3-16", false},
		{"epoch bumped by the fix, version still older", "1:1.2-3", "2:1.3-1", false},
		{"higher epoch installed", "3:1.0-1", "2:9.9-9", false},
		{"no fix named", "1.31.8-.el10", "", false},
		{"no installed version", "", "2:1.26.3-16.el10_3.1", false},
	}
	for _, tt := range tests {
		if got := ForeignRPM(tt.installed, tt.fixedIn); got != tt.want {
			t.Errorf("%s: ForeignRPM(%q, %q) = %v, want %v", tt.name, tt.installed, tt.fixedIn, got, tt.want)
		}
	}
}
