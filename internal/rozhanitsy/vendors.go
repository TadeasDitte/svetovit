package rozhanitsy

func (r *CheckResponse) Remove(match func(product string) bool) {
	keepV := r.Vulnerable[:0]
	for _, v := range r.Vulnerable {
		if !match(v.Product) {
			keepV = append(keepV, v)
		}
	}
	r.Vulnerable = keepV
	keepU := r.Unmatched[:0]
	for _, u := range r.Unmatched {
		if !match(u.Product) {
			keepU = append(keepU, u)
		}
	}
	r.Unmatched = keepU
	for loc, entry := range r.ByLocation {
		var vs []Vulnerability
		for _, v := range entry.Vulnerable {
			if !match(v.Product) {
				vs = append(vs, v)
			}
		}
		var us []UnmatchedComponent
		for _, u := range entry.Unmatched {
			if !match(u.Product) {
				us = append(us, u)
			}
		}
		if len(vs) == 0 && len(us) == 0 {
			delete(r.ByLocation, loc)
			continue
		}
		entry.Vulnerable, entry.Unmatched = vs, us
	}
}

// Reclassify files every finding drop picks out under Unmatched with note instead, keeping a package
// whose advisories are not evidence of a missing patch visible without counting it as vulnerable.
// It returns how many findings were moved.
func (r *CheckResponse) Reclassify(drop func(Vulnerability) bool, note string) int {
	move := func(vulns []Vulnerability) ([]Vulnerability, []UnmatchedComponent) {
		kept := vulns[:0]
		var moved []UnmatchedComponent
		for _, v := range vulns {
			if !drop(v) {
				kept = append(kept, v)
				continue
			}
			moved = append(moved, UnmatchedComponent{
				Vendor:           v.Vendor,
				Product:          v.Product,
				InstalledVersion: v.InstalledVersion,
				LocalID:          v.LocalID,
				Note:             note,
			})
		}
		return kept, moved
	}

	vulnerable, moved := move(r.Vulnerable)
	r.Vulnerable = vulnerable
	r.Unmatched = append(r.Unmatched, moved...)
	for _, entry := range r.ByLocation {
		kept, movedHere := move(entry.Vulnerable)
		entry.Vulnerable = kept
		entry.Unmatched = append(entry.Unmatched, movedHere...)
	}
	r.dedupe()
	return len(moved)
}

func (r *CheckResponse) Merge(other *CheckResponse) {
	r.Vulnerable = append(r.Vulnerable, other.Vulnerable...)
	r.Unmatched = append(r.Unmatched, other.Unmatched...)
	for loc, entry := range other.ByLocation {
		dst := r.locationEntry(loc)
		dst.Vulnerable = append(dst.Vulnerable, entry.Vulnerable...)
		dst.Unmatched = append(dst.Unmatched, entry.Unmatched...)
	}
}

// Several ranges of one product, filed under different vendor names, can match the same advisory; the first one wins.
func (r *CheckResponse) dedupe() {
	r.Vulnerable = uniqueVulnerabilities(r.Vulnerable)
	r.Unmatched = uniqueUnmatched(r.Unmatched)
	for _, entry := range r.ByLocation {
		entry.Vulnerable = uniqueVulnerabilities(entry.Vulnerable)
		entry.Unmatched = uniqueUnmatched(entry.Unmatched)
	}
}

func uniqueVulnerabilities(vulns []Vulnerability) []Vulnerability {
	type key struct{ localID, vendor, product, version, id string }
	seen := make(map[key]bool, len(vulns))
	out := vulns[:0]
	for _, v := range vulns {
		k := key{v.LocalID, v.Vendor, v.Product, v.InstalledVersion, v.CVEID}
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}

func uniqueUnmatched(unmatched []UnmatchedComponent) []UnmatchedComponent {
	seen := make(map[UnmatchedComponent]bool, len(unmatched))
	out := unmatched[:0]
	for _, u := range unmatched {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
