package rtnl

// DeleteMatches reports whether the kernel's rule delete would take x for the
// request req. It follows rule_find() in net/core/fib_rules.c (Linux 6.12)
// together with the family's ops->compare, fib4_rule_compare() in
// net/ipv4/fib_rules.c and fib6_rule_compare() in net/ipv6/fib6_rules.c, which
// fib_nl_delrule() calls on the rule fib_nl2rule() built from the request.
// Every test is "the request does not set the attribute, or it equals the
// rule's", and NOT SET MEANS ZERO: an explicit zero fwmark, fwmask, table,
// action, ip protocol, tos, protocol or source/destination prefix length in
// the request is a wildcard (`rule->mark && r->mark != rule->mark`), exactly
// as an absent attribute is. suppress_prefixlen and suppress_ifgroup are
// wildcards only when absent (their unset value is -1). The priority is
// compared when the request carries one, which Rule.Marshal always does. The
// invert flag is not compared. The kernel removes the first rule, in priority
// order, for which this is true; the policy model, the tests' fake kernel and
// the owner share this one definition.
func DeleteMatches(req, x Rule) bool {
	if req.Priority != x.Priority { // user_priority && r->pref != rule->pref
		return false
	}
	if req.Action != 0 && req.Action != x.Action { // rule->action && r->action != rule->action
		return false
	}
	if req.Table != 0 && req.Table != x.Table { // rule->table && r->table != rule->table
		return false
	}
	if req.IifName != "" && req.IifName != x.IifName { // rule->iifname[0] && memcmp
		return false
	}
	if req.OifName != "" && req.OifName != x.OifName { // rule->oifname[0] && memcmp
		return false
	}
	if req.FwMark.OK && req.FwMark.V != 0 && req.FwMark != x.FwMark { // rule->mark && r->mark != rule->mark
		return false
	}
	if req.FwMask.OK && req.FwMask.V != 0 && req.FwMask != x.FwMask { // rule->mark_mask && ...
		return false
	}
	if req.SuppressIfGroup.OK && req.SuppressIfGroup != x.SuppressIfGroup { // rule->suppress_ifgroup != -1 && ...
		return false
	}
	if req.SuppressPrefixLen.OK && req.SuppressPrefixLen != x.SuppressPrefixLen { // rule->suppress_prefixlen != -1 && ...
		return false
	}
	if req.L3Mdev.OK && req.L3Mdev.V != 0 && req.L3Mdev != x.L3Mdev { // rule->l3mdev && ...
		return false
	}
	if req.IPProto.OK && req.IPProto.V != 0 && req.IPProto != x.IPProto { // rule->ip_proto && ...
		return false
	}
	if req.Protocol.OK && req.Protocol.V != 0 && req.Protocol != x.Protocol { // rule->proto && ...
		return false
	}
	// ops->compare: fib4_rule_compare / fib6_rule_compare.
	if req.Src.IsValid() && req.Src.Bits() > 0 && req.Src != x.Src { // frh->src_len && (src_len or src differs)
		return false
	}
	if req.Dst.IsValid() && req.Dst.Bits() > 0 && req.Dst != x.Dst { // frh->dst_len && (dst_len or dst differs)
		return false
	}
	if req.Tos != 0 && req.Tos != x.Tos { // frh->tos && rule->tos != frh->tos
		return false
	}
	// uid ranges, ports, tunnel ids and attributes of newer kernels: compared
	// when the request carries them.
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
