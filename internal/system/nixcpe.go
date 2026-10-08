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

type CPE struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

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

func stderrOf(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return ": " + strings.TrimSpace(string(exitErr.Stderr))
	}
	return ""
}
