package scanner

import (
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
