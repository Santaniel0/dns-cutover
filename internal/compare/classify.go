package compare

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// observation is everything the servers said about one question, indexed
// like Config.Old and Config.New.
type observation struct {
	q   dnsq.Question
	old []answer
	new []answer
}

type key struct {
	name rr.Name
	typ  rr.Type
}

// outcome is how one new server's RRset relates to the old reference.
type outcome uint8

const (
	outMatch outcome = iota
	outMissing
	outDifferent
	outExtra
	outTTL
	outProxied
	// outExplained is a difference already covered by another finding: the
	// proxy addresses that replaced a proxied CNAME.
	outExplained
)

var outcomeKind = map[outcome]finding.Kind{
	outMissing:   finding.Missing,
	outDifferent: finding.Different,
	outExtra:     finding.Extra,
	outTTL:       finding.TTLOnly,
	outProxied:   finding.Proxied,
}

var kindSeverity = map[finding.Kind]finding.Severity{
	finding.Missing:   finding.Blocker,
	finding.Different: finding.Blocker,
	finding.Extra:     finding.Warning,
	finding.TTLOnly:   finding.Warning,
	finding.Proxied:   finding.Info,
}

// group is a set of new servers that gave the same outcome with the same data.
type group struct {
	outcome outcome
	set     rr.Set
	servers []int
}

type failure struct {
	count int
	first string
}

type classifier struct {
	cfg   Config
	byKey map[key]*observation
}

func classify(cfg Config, obs []observation) ([]finding.Finding, Stats) {
	c := classifier{cfg: cfg, byKey: make(map[key]*observation, len(obs))}
	for i := range obs {
		c.byKey[key{obs[i].q.Name, obs[i].q.Type}] = &obs[i]
	}

	var (
		out     []finding.Finding
		stats   = Stats{Questions: len(obs)}
		oldFail = make([]failure, len(cfg.Old))
		newFail = make([]failure, len(cfg.New))
		noRef   int
	)
	for i := range obs {
		o := &obs[i]
		tally(oldFail, o.old)
		tally(newFail, o.new)

		ref, refIdx, ok := reference(o.old)
		if !ok {
			noRef++
			continue
		}
		out = append(out, c.oldDisagreements(o, ref, refIdx)...)
		if !ref.set.Empty() && ref.set.TTL > stats.MaxTTL {
			stats.MaxTTL, stats.MaxTTLName, stats.MaxTTLType = ref.set.TTL, o.q.Name, o.q.Type
		}

		hasData := !ref.set.Empty()
		matched := true
		for _, g := range c.groupNew(o, ref) {
			if !g.set.Empty() {
				hasData = true
			}
			if g.outcome == outMatch {
				continue
			}
			matched = false
			if g.outcome != outExplained {
				out = append(out, c.finding(o, ref, g))
			}
		}
		if hasData {
			stats.RRsets++
			if matched {
				stats.Matched++
			}
		}
	}

	c.upgradeProxiedTargets(out, obs)
	out = append(out, c.failures(oldFail, newFail, noRef)...)
	finding.Sort(out)
	return out, stats
}

func tally(fails []failure, answers []answer) {
	for i, a := range answers {
		if a.status == statusOK {
			continue
		}
		fails[i].count++
		if fails[i].first == "" {
			fails[i].first = a.problem()
		}
	}
}

// reference picks the answer of the first old server that answered. The
// other old servers are checked against it separately.
func reference(old []answer) (answer, int, bool) {
	for i, a := range old {
		if a.status == statusOK {
			return a, i, true
		}
	}
	return answer{}, 0, false
}

func (c *classifier) oldDisagreements(o *observation, ref answer, refIdx int) []finding.Finding {
	var out []finding.Finding
	for i, a := range o.old {
		if i == refIdx || a.status != statusOK || a.set.SameData(ref.set) {
			continue
		}
		out = append(out, finding.Finding{
			Kind:     finding.OldInconsistent,
			Severity: finding.Warning,
			Name:     o.q.Name,
			Type:     o.q.Type,
			Servers:  []string{c.cfg.Old[i].String()},
			Old:      ref.set.Data,
			Detail: fmt.Sprintf("%s answers %s; the comparison uses %s",
				c.cfg.Old[i], describe(a.set), c.cfg.Old[refIdx]),
		})
	}
	return out
}

func (c *classifier) groupNew(o *observation, ref answer) []group {
	var groups []group
	for i, a := range o.new {
		if a.status != statusOK {
			continue
		}
		oc := c.applyProxy(o, i, a, compareSets(ref.set, a.set))
		gi := slices.IndexFunc(groups, func(g group) bool {
			return g.outcome == oc && g.set.SameData(a.set) && g.set.TTL == a.set.TTL
		})
		if gi < 0 {
			groups = append(groups, group{outcome: oc, set: a.set})
			gi = len(groups) - 1
		}
		groups[gi].servers = append(groups[gi].servers, i)
	}
	return groups
}

func compareSets(was, now rr.Set) outcome {
	switch {
	case was.Empty() && now.Empty():
		return outMatch
	case was.SameData(now):
		if was.TTL != now.TTL {
			return outTTL
		}
		return outMatch
	case now.Empty():
		return outMissing
	case was.Empty():
		return outExtra
	default:
		return outDifferent
	}
}

// applyProxy recognizes records that a proxying provider (Cloudflare's
// orange cloud) rewrites: A/AAAA answers become proxy addresses, and a
// proxied CNAME is answered with proxy addresses instead of the CNAME.
func (c *classifier) applyProxy(o *observation, server int, a answer, oc outcome) outcome {
	if len(c.cfg.Proxy) == 0 {
		return oc
	}
	switch o.q.Type {
	case rr.TypeA, rr.TypeAAAA:
		if (oc != outDifferent && oc != outExtra) || !c.cfg.Proxy.ContainsAll(a.set.Addrs()) {
			return oc
		}
		if cn, ok := c.byKey[key{o.q.Name, rr.TypeCNAME}]; ok {
			if ref, _, ok := reference(cn.old); ok && !ref.set.Empty() {
				return outExplained
			}
		}
		return outProxied
	case rr.TypeCNAME:
		if oc == outMissing && c.servesProxy(o.q.Name, server) {
			return outProxied
		}
	}
	return oc
}

func (c *classifier) servesProxy(name rr.Name, server int) bool {
	for _, t := range []rr.Type{rr.TypeA, rr.TypeAAAA} {
		o, ok := c.byKey[key{name, t}]
		if !ok || server >= len(o.new) || o.new[server].status != statusOK {
			continue
		}
		if c.cfg.Proxy.ContainsAll(o.new[server].set.Addrs()) {
			return true
		}
	}
	return false
}

func (c *classifier) finding(o *observation, ref answer, g group) finding.Finding {
	kind := outcomeKind[g.outcome]
	f := finding.Finding{
		Kind:     kind,
		Severity: kindSeverity[kind],
		Name:     o.q.Name,
		Type:     o.q.Type,
		Old:      ref.set.Data,
		New:      g.set.Data,
		OldTTL:   ref.set.TTL,
		NewTTL:   g.set.TTL,
	}
	if len(g.servers) < len(c.cfg.New) {
		for _, i := range g.servers {
			f.Servers = append(f.Servers, c.cfg.New[i].String())
		}
	}
	if g.outcome == outProxied {
		if o.q.Type == rr.TypeCNAME {
			f.Detail = "answered with proxy addresses instead of the CNAME; HTTP(S) goes through the proxy, other protocols do not reach the target"
			f.New = c.proxyAddrs(o.q.Name, g.servers[0])
		} else {
			f.Detail = "new addresses belong to proxy ranges; HTTP(S) goes through the proxy, other protocols do not reach the origin"
		}
	}
	return f
}

func (c *classifier) proxyAddrs(name rr.Name, server int) []string {
	var out []string
	for _, t := range []rr.Type{rr.TypeA, rr.TypeAAAA} {
		if o, ok := c.byKey[key{name, t}]; ok && server < len(o.new) {
			out = append(out, o.new[server].set.Data...)
		}
	}
	return out
}

// upgradeProxiedTargets turns a Proxied finding into a blocker when the name
// receives mail or other non-HTTP traffic: Cloudflare's proxy only speaks
// HTTP(S), so an MX host behind it silently stops receiving mail.
func (c *classifier) upgradeProxiedTargets(fs []finding.Finding, obs []observation) {
	targets := make(map[rr.Name]string)
	for _, o := range obs {
		if o.q.Type != rr.TypeMX && o.q.Type != rr.TypeSRV {
			continue
		}
		for _, a := range slices.Concat(o.old, o.new) {
			if a.status != statusOK {
				continue
			}
			for _, t := range a.set.Targets() {
				if _, seen := targets[t]; !seen {
					targets[t] = fmt.Sprintf("%s target of %s", o.q.Type, o.q.Name)
				}
			}
		}
	}
	for i := range fs {
		why, ok := targets[fs[i].Name]
		if fs[i].Kind != finding.Proxied || !ok {
			continue
		}
		fs[i].Kind = finding.ProxiedTarget
		fs[i].Severity = finding.Blocker
		fs[i].Detail = why + "; clients connecting to proxy addresses will not reach the server (the proxy only passes HTTP/HTTPS)"
	}
}

func (c *classifier) failures(oldFail, newFail []failure, noRef int) []finding.Finding {
	var out []finding.Finding
	total := len(c.byKey)
	add := func(srv dnsq.Server, f failure, sev finding.Severity) {
		out = append(out, finding.Finding{
			Kind:     finding.QueryFailed,
			Severity: sev,
			Name:     c.cfg.Zone,
			Servers:  []string{srv.String()},
			Detail:   fmt.Sprintf("%d of %d queries got no usable answer, first: %s", f.count, total, f.first),
		})
	}
	for i, f := range newFail {
		if f.count > 0 {
			add(c.cfg.New[i], f, finding.Blocker)
		}
	}
	// A failing old server is only a warning while another old server
	// answered; questions no old server answered are counted below.
	for i, f := range oldFail {
		if f.count > 0 {
			add(c.cfg.Old[i], f, finding.Warning)
		}
	}
	if noRef > 0 {
		out = append(out, finding.Finding{
			Kind:     finding.QueryFailed,
			Severity: finding.Blocker,
			Name:     c.cfg.Zone,
			Detail:   fmt.Sprintf("%d questions got no usable answer from any old server and were not compared", noRef),
		})
	}
	return out
}

func describe(s rr.Set) string {
	if s.Empty() {
		return "nothing"
	}
	return strings.Join(s.Data, ", ")
}
