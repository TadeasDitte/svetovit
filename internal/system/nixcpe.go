package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CPE is the NVD vendor/product nixpkgs records for a package in meta.identifiers.
type CPE struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// nixCPEExpr looks each name up in the registry's nixpkgs and returns {name: {vendor, product}} for
// those whose meta.identifiers.cpeParts carries a vendor. Names that are no attribute, throw when
// evaluated (aliases) or have no CPE are left out. Names arrive through SVETOVIT_NAMES.
const nixCPEExpr = `
let
  pkgs = (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
  names = builtins.fromJSON (builtins.getEnv "SVETOVIT_NAMES");
  lookup = n:
    let
      p = pkgs.${n}.meta.identifiers.cpeParts or { };
      v = if p ? vendor && p ? product then { inherit (p) vendor product; } else null;
      r = builtins.tryEval (builtins.deepSeq v v);
    in if pkgs ? ${n} && r.success && r.value != null then [ { name = n; value = r.value; } ] else [ ];
in builtins.listToAttrs (builtins.concatMap lookup names)
`

// NixCPEs resolves nixpkgs CPE vendor/product pairs for the given package names. Packages without
// CPE metadata, which is most of nixpkgs, are simply absent from the result.
func NixCPEs(names []string) (map[string]CPE, error) {
	if len(names) == 0 {
		return nil, nil
	}
	list, err := json.Marshal(names)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nix", "--extra-experimental-features", "nix-command flakes",
		"eval", "--impure", "--json", "--expr", nixCPEExpr)
	cmd.Env = append(os.Environ(), "SVETOVIT_NAMES="+string(list))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("resolving nixpkgs CPEs: %w%s", err, stderrOf(err))
	}

	cpes := make(map[string]CPE)
	if err := json.Unmarshal(out, &cpes); err != nil {
		return nil, fmt.Errorf("decoding nixpkgs CPEs: %w", err)
	}
	return cpes, nil
}

// stderrOf appends a failed command's stderr, which holds nix's actual error message.
func stderrOf(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return ": " + strings.TrimSpace(string(exitErr.Stderr))
	}
	return ""
}
