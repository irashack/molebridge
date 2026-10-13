package rtnl

// DeleteMatches reports whether the kernel's rule delete (fib_nl_delrule,
// rule_find) would take x for the request req: every attribute req gives is the
// same on x. The invert flag is not compared. The kernel removes the first
// rule, in priority order, for which this is true; the policy model and the
// tests' fake kernel share this one definition.
func DeleteMatches(req, x Rule) bool {
	if req.Priority != x.Priority {
		return false
	}
	if req.Action != 0 && req.Action != x.Action {
		return false
	}
	if req.Table != 0 && req.Table != x.Table {
		return false
	}
	if req.IifName != "" && req.IifName != x.IifName {
		return false
	}
	if req.OifName != "" && req.OifName != x.OifName {
		return false
	}
	if req.FwMark.OK && req.FwMark != x.FwMark {
		return false
	}
	if req.FwMask.OK && req.FwMask != x.FwMask {
		return false
	}
	if req.SuppressPrefixLen.OK && req.SuppressPrefixLen != x.SuppressPrefixLen {
		return false
	}
	if req.IPProto.OK && req.IPProto != x.IPProto {
		return false
	}
	if req.Src.IsValid() && req.Src != x.Src {
		return false
	}
	if req.Dst.IsValid() && req.Dst != x.Dst {
		return false
	}
	if req.Tos != 0 && req.Tos != x.Tos {
		return false
	}
	for _, u := range req.Unknown {
		found := false
		for _, v := range x.Unknown {
			if u.Type == v.Type && string(u.Data) == string(v.Data) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
