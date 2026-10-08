package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TadeasDitte/Svetovit/detectors"
	"github.com/TadeasDitte/Svetovit/internal/detector"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedDetectorsLoad(t *testing.T) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatalf("embedded detectors invalid: %v", err)
	}
	if len(reg.All()) == 0 {
		t.Fatal("no detectors loaded")
	}
}

func TestScanFindsWordPressAndSkipsNodeModules(t *testing.T) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	site := filepath.Join(root, "vhost1")
	write(t, filepath.Join(site, "wp-load.php"), "<?php")
	write(t, filepath.Join(site, "wp-includes/version.php"), "<?php\n$wp_version = '6.4.2';\n")
	write(t, filepath.Join(site, "wp-content/plugins/foo/readme.txt"), "Stable tag: 1.2.3\n")
	// a decoy inside node_modules must not be discovered
	write(t, filepath.Join(root, "node_modules/x/wp-load.php"), "<?php")
	write(t, filepath.Join(root, "node_modules/x/wp-includes/version.php"), "$wp_version = '1.0';")

	got, err := New(reg, UnlimitedDepth).Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, c := range got {
		versions[c.Product] = c.Version
	}
	if versions["wordpress"] != "6.4.2" || versions["foo"] != "1.2.3" || len(got) != 2 {
		t.Fatalf("unexpected components: %+v", got)
	}
}

func scanVersions(t *testing.T, root string) map[string]string {
	t.Helper()
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	got, err := New(reg, UnlimitedDepth).Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, c := range got {
		versions[c.Product] = c.Version
	}
	return versions
}

func TestWordPressPrefersHeaderOverReadmeAndFindsThemes(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "wp-load.php"), "<?php")
	write(t, filepath.Join(root, "wp-includes/version.php"), "$wp_version = '6.5';")
	write(t, filepath.Join(root, "wp-content/plugins/bar/index.php"), "<?php // Silence is golden")
	write(t, filepath.Join(root, "wp-content/plugins/bar/bar.php"), "<?php\n/*\n * Plugin Name: Bar\n * Version: 2.0.1\n */")
	write(t, filepath.Join(root, "wp-content/plugins/bar/readme.txt"), "Stable tag: 9.9.9")
	write(t, filepath.Join(root, "wp-content/themes/twentytest/style.css"), "/*\nTheme Name: T\nVersion: 3.1\n*/")

	v := scanVersions(t, root)
	if v["bar"] != "2.0.1" || v["twentytest"] != "3.1" {
		t.Fatalf("unexpected versions: %v", v)
	}
}

func TestJoomlaManifestAndDrupalDevVersion(t *testing.T) {
	root := t.TempDir()
	j := filepath.Join(root, "joomla")
	write(t, filepath.Join(j, "administrator/manifests/files/joomla.xml"), "<extension><version>5.0.1</version></extension>")
	write(t, filepath.Join(j, "plugins/system/myplug/myplug.xml"), "<extension><version>1.4.0</version></extension>")

	d := filepath.Join(root, "drupal")
	write(t, filepath.Join(d, "core/lib/Drupal.php"), "const VERSION = '10.2.0';")
	write(t, filepath.Join(d, "modules/contrib/views_x/views_x.info.yml"), "name: X\nversion: '2.0.x-dev'\n")

	v := scanVersions(t, root)
	if v["joomla"] != "5.0.1" || v["myplug"] != "1.4.0" || v["drupal"] != "10.2.0" || v["views_x"] != "2.0.x-dev" {
		t.Fatalf("unexpected versions: %v", v)
	}
}

func TestExtensionsAreSentWithoutVendor(t *testing.T) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write(t, filepath.Join(root, "wp-load.php"), "<?php")
	write(t, filepath.Join(root, "wp-includes/version.php"), "$wp_version = '6.5';")
	write(t, filepath.Join(root, "wp-content/plugins/foo/readme.txt"), "Stable tag: 1.0")
	got, err := New(reg, UnlimitedDepth).Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c.Product == "foo" && c.Vendor != "" {
			t.Errorf("plugin sent with vendor %q", c.Vendor)
		}
	}
}

func wpSite(t *testing.T, dir string) {
	t.Helper()
	write(t, filepath.Join(dir, "wp-load.php"), "<?php")
	write(t, filepath.Join(dir, "wp-includes/version.php"), "$wp_version = '6.5';")
}

func locations(t *testing.T, root string, depth int) map[string]bool {
	t.Helper()
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	got, err := New(reg, depth).Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	locs := map[string]bool{}
	for _, c := range got {
		locs[c.LocalID] = true
	}
	return locs
}

func TestNestedSiteIsNotReportedButItsLockfileIs(t *testing.T) {
	root := t.TempDir()
	outer := filepath.Join(root, "outer")
	wpSite(t, outer)
	wpSite(t, filepath.Join(outer, "blog")) // an install inside an install is not a separate site
	write(t, filepath.Join(outer, "blog/composer.lock"), `{"packages":[{"name":"a/b","version":"1.0.0"}]}`)

	locs := locations(t, root, UnlimitedDepth)
	if !locs[outer] || locs[filepath.Join(outer, "blog")] {
		t.Errorf("want only the outer site, got %v", locs)
	}
	if !locs[filepath.Join(outer, "blog/composer.lock")] {
		t.Errorf("lock file inside a site should still be found: %v", locs)
	}
}

func TestDepthLimitsSitesAndLockfiles(t *testing.T) {
	root := t.TempDir()
	wpSite(t, filepath.Join(root, "a"))                                                                     // depth 1
	wpSite(t, filepath.Join(root, "x/y/deep"))                                                              // depth 3
	write(t, filepath.Join(root, "a/sub/composer.lock"), `{"packages":[{"name":"a/b","version":"1.0.0"}]}`) // depth 3

	shallow := locations(t, root, 1)
	if !shallow[filepath.Join(root, "a")] || shallow[filepath.Join(root, "x/y/deep")] || shallow[filepath.Join(root, "a/sub/composer.lock")] {
		t.Errorf("depth 1: %v", shallow)
	}
	full := locations(t, root, UnlimitedDepth)
	if !full[filepath.Join(root, "x/y/deep")] || !full[filepath.Join(root, "a/sub/composer.lock")] {
		t.Errorf("unlimited depth: %v", full)
	}
}

func TestUnreadableSubdirectoryDoesNotAbortScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	root := t.TempDir()
	wpSite(t, filepath.Join(root, "ok"))
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	if locs := locations(t, root, UnlimitedDepth); !locs[filepath.Join(root, "ok")] {
		t.Errorf("readable site lost: %v", locs)
	}
}

func TestMissingTargetIsAnError(t *testing.T) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(reg, UnlimitedDepth).Scan(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("want an error for a missing target")
	}
}

func BenchmarkScanHostingTree(b *testing.B) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		b.Fatal(err)
	}
	root := b.TempDir()
	for i := 0; i < 2000; i++ {
		site := filepath.Join(root, fmt.Sprintf("tenant%04d", i/20), fmt.Sprintf("site%d", i), "public_html")
		for _, f := range []string{"wp-load.php", "wp-includes/version.php", "wp-content/plugins/p1/readme.txt", "wp-content/uploads/2026/01/x.jpg", "wp-content/themes/t/style.css"} {
			p := filepath.Join(site, f)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte("$wp_version = '6.5'; Stable tag: 1.0 Version: 1.0"), 0o644)
		}
		for j := 0; j < 5; j++ { // noise: dirs that are not installs
			os.MkdirAll(filepath.Join(root, fmt.Sprintf("tenant%04d", i/20), fmt.Sprintf("logs%d_%d", i, j)), 0o755)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := New(reg, UnlimitedDepth).Scan(root); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInstallUploadDirsAreNotSearched(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "site")
	wpSite(t, site)
	lock := `{"packages":[{"name":"a/b","version":"1.0.0"}]}`
	write(t, filepath.Join(site, "wp-content/uploads/x/composer.lock"), lock)
	write(t, filepath.Join(site, "wp-content/themes/t/composer.lock"), lock)
	write(t, filepath.Join(root, "other/wp-content/uploads/composer.lock"), lock)

	locs := locations(t, root, UnlimitedDepth)
	if locs[filepath.Join(site, "wp-content/uploads/x/composer.lock")] {
		t.Errorf("lock file under wp-content/uploads should not be found: %v", locs)
	}
	if !locs[filepath.Join(site, "wp-content/themes/t/composer.lock")] || !locs[filepath.Join(root, "other/wp-content/uploads/composer.lock")] {
		t.Errorf("lock files outside skipped dirs lost: %v", locs)
	}
}
