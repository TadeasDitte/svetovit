package detectors_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TadeasDitte/Svetovit/detectors"
	"github.com/TadeasDitte/Svetovit/internal/detector"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, name string) *detector.Detector {
	t.Helper()
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range reg.All() {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no embedded detector %q", name)
	return nil
}

func TestEmbeddedDetectorSet(t *testing.T) {
	reg, err := detector.LoadFS(detectors.FS)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range reg.All() {
		got[d.Name] = true
	}
	for _, name := range []string{"drupal", "joomla", "laravel", "prestashop", "wordpress"} {
		if !got[name] {
			t.Errorf("missing detector %q", name)
		}
	}
}

func pluginVersions(t *testing.T, d *detector.Detector, root string) map[string]string {
	t.Helper()
	plugins, err := d.DetectPlugins(root, detector.NewListing())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range plugins {
		got[p.Name] = p.Version
	}
	return got
}

func expect(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestWordPress(t *testing.T) {
	d := get(t, "wordpress")
	root := t.TempDir()
	write(t, root, "wp-load.php", "<?php")
	write(t, root, "wp-includes/version.php", "<?php\n$wp_version = \"6.5.1\";\n$wp_db_version = 57155;\n")
	write(t, root, "wp-content/plugins/akismet/akismet.php",
		"<?php\n/**\n * Plugin Name: Akismet\n * Description: Spam protection\n * Version: 5.3.2\n * Author: Automattic\n */\n")
	write(t, root, "wp-content/plugins/legacy/legacy.php",
		"<?php\n/*\nPlugin Name: Legacy\nVersion: 0.9\n*/\n")
	write(t, root, "wp-content/plugins/readme-only/readme.txt", "=== X ===\nStable tag: 2.4.0\n")
	write(t, root, "wp-content/plugins/index.php", "<?php // Silence is golden")
	write(t, root, "wp-content/themes/twenty/style.css", "/*\nTheme Name: Twenty\nVersion: 3.1\n*/\n")

	if !detect(t, d, root) {
		t.Fatal("not detected")
	}
	if v, err := d.CoreVersion(root, detector.NewListing()); err != nil || v != "6.5.1" {
		t.Fatalf("core = %q, %v", v, err)
	}
	expect(t, pluginVersions(t, d, root), map[string]string{
		"akismet": "5.3.2", "legacy": "0.9", "readme-only": "2.4.0", "twenty": "3.1",
	})
}

func TestDrupal(t *testing.T) {
	d := get(t, "drupal")
	root := t.TempDir()
	write(t, root, "core/lib/Drupal.php", "<?php\nclass Drupal {\n  const VERSION = '10.2.3';\n}\n")
	write(t, root, "modules/contrib/token/token.info.yml", "name: Token\nversion: '8.x-1.12'\n")
	write(t, root, "modules/custom_mod/custom_mod.info.yml", "name: Custom\nversion: 1.0.x-dev\n")
	write(t, root, "themes/olivero/olivero.info.yml", "name: Olivero\nversion: \"10.2.3\"\n")
	write(t, root, "modules/nover/nover.info.yml", "name: No version\n")

	if !detect(t, d, root) {
		t.Fatal("not detected")
	}
	if v, err := d.CoreVersion(root, detector.NewListing()); err != nil || v != "10.2.3" {
		t.Fatalf("core = %q, %v", v, err)
	}
	expect(t, pluginVersions(t, d, root), map[string]string{
		"token": "8.x-1.12", "custom_mod": "1.0.x-dev", "olivero": "10.2.3",
	})
}

func TestJoomla(t *testing.T) {
	d := get(t, "joomla")
	root := t.TempDir()
	write(t, root, "administrator/manifests/files/joomla.xml", "<extension>\n<version>5.0.3</version>\n</extension>")
	write(t, root, "plugins/system/cache/cache.xml", "<extension><version>5.0.0</version></extension>")
	write(t, root, "administrator/components/com_foo/foo.xml", "<extension><version>1.4.2</version></extension>")
	write(t, root, "modules/mod_bar/mod_bar.xml", "<extension><version>2.0</version></extension>")
	write(t, root, "templates/cassiopeia/templateDetails.xml", "<extension><version>4.1</version></extension>")
	write(t, root, "templates/cassiopeia/other.xml", "<extension><version>9.9</version></extension>")

	if !detect(t, d, root) {
		t.Fatal("not detected")
	}
	if v, err := d.CoreVersion(root, detector.NewListing()); err != nil || v != "5.0.3" {
		t.Fatalf("core = %q, %v", v, err)
	}
	expect(t, pluginVersions(t, d, root), map[string]string{
		"cache": "5.0.0", "com_foo": "1.4.2", "mod_bar": "2.0", "cassiopeia": "4.1",
	})
}

func TestLaravel(t *testing.T) {
	d := get(t, "laravel")
	root := t.TempDir()
	write(t, root, "artisan", "#!/usr/bin/env php")
	write(t, root, "vendor/laravel/framework/src/Illuminate/Foundation/Application.php",
		"<?php\nclass Application {\n    const VERSION = '11.9.2';\n}\n")

	if !detect(t, d, root) {
		t.Fatal("not detected")
	}
	if v, err := d.CoreVersion(root, detector.NewListing()); err != nil || v != "11.9.2" {
		t.Fatalf("core = %q, %v", v, err)
	}
}

func TestPrestaShop(t *testing.T) {
	d := get(t, "prestashop")
	root := t.TempDir()
	write(t, root, "config/settings.inc.php", "<?php\ndefine('_PS_VERSION_', '8.1.5');\n")
	write(t, root, "modules/ps_cart/config.xml", "<module><version><![CDATA[2.0.1]]></version></module>")
	write(t, root, "themes/classic/config/theme.yml", "name: classic\nversion: 1.7.0\n")

	if !detect(t, d, root) {
		t.Fatal("not detected")
	}
	if v, err := d.CoreVersion(root, detector.NewListing()); err != nil || v != "8.1.5" {
		t.Fatalf("core = %q, %v", v, err)
	}
	expect(t, pluginVersions(t, d, root), map[string]string{"ps_cart": "2.0.1", "classic": "1.7.0"})

	// AppKernel is the fallback version source.
	alt := t.TempDir()
	write(t, alt, "config/settings.inc.php", "<?php // no version here")
	write(t, alt, "app/AppKernel.php", "<?php\nclass AppKernel { const VERSION = '1.7.8.10'; }")
	if v, err := d.CoreVersion(alt, detector.NewListing()); err != nil || v != "1.7.8.10" {
		t.Fatalf("fallback core = %q, %v", v, err)
	}
}

func detect(t *testing.T, d *detector.Detector, root string) bool {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	return d.DetectIn(root, func(name string) bool { return names[name] })
}
