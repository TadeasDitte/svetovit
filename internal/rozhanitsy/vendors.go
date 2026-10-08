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

func (r *CheckResponse) Merge(other *CheckResponse) {
	r.Vulnerable = append(r.Vulnerable, other.Vulnerable...)
	r.Unmatched = append(r.Unmatched, other.Unmatched...)
	for loc, entry := range other.ByLocation {
		dst := r.locationEntry(loc)
		dst.Vulnerable = append(dst.Vulnerable, entry.Vulnerable...)
		dst.Unmatched = append(dst.Unmatched, entry.Unmatched...)
	}
}
