package check

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
	"github.com/atsvetko/directory-auditor/internal/tier0"
)

// Finding is one check firing on one object.
type Finding struct {
	CheckID  string            `json:"check_id"`
	Severity string            `json:"severity"`
	DN       string            `json:"dn"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// CheckResult summarises one pack's run: findings, or why it did not run.
type CheckResult struct {
	ID       string    `json:"id"`
	Title    Text      `json:"title"`
	Domain   string    `json:"domain"`
	Tier     int       `json:"tier"`
	Severity string    `json:"severity"`
	Status   string    `json:"status"`                // "pass", "fail", "skipped"
	Skip     string    `json:"skip_reason,omitempty"` // "provider", "tier", "error"
	Matched  int       `json:"objects_matched"`
	Findings []Finding `json:"findings,omitempty"`
	Signed   bool      `json:"signed"`
	Duration string    `json:"duration"`

	Attack      []string               `json:"attack,omitempty"`
	Remediation map[string]Remediation `json:"remediation,omitempty"`
	References  []Reference            `json:"references,omitempty"`
}

// Inventory is what the engine learned about the directory independent of any
// check: how much was collected, what could not be, and who is Tier 0 and why.
type Inventory struct {
	Objects    int                `json:"objects"`
	Collected  time.Time          `json:"collected_at"`
	Identity   string             `json:"identity,omitempty"`
	Domain     string             `json:"domain,omitempty"`
	BaseDN     string             `json:"base_dn,omitempty"`
	Tier0      []Tier0Entry       `json:"tier0"`
	Unresolved []string           `json:"tier0_unresolved,omitempty"`
	NotRead    []snapshot.Skipped `json:"not_collected,omitempty"`
	Duration   string             `json:"collection_duration,omitempty"`
	Searches   int                `json:"searches"`
}

// Tier0Entry is one Tier-0 principal or object with the path that makes it so.
type Tier0Entry struct {
	DN     string `json:"dn"`
	Reason string `json:"reason"`
}

// Result is the whole analysis — the input to every report format.
type Result struct {
	SnapshotHash string        `json:"snapshot_hash"`
	Provider     string        `json:"provider"`
	Dialect      string        `json:"dialect"`
	Target       string        `json:"target"`
	Tier         int           `json:"tier"`
	Checks       []CheckResult `json:"checks"`
	Counts       Counts        `json:"counts"`
	Score        int           `json:"score"` // 0–100, 100 = nothing found
	AnalysedAt   time.Time     `json:"analysed_at"`
	Unsigned     bool          `json:"unsigned_packs"` // true when any loaded pack was unsigned
	Inventory    Inventory     `json:"inventory"`
}

// Counts are the honest states shown at the top of every report (AR-12).
type Counts struct {
	Checked  int            `json:"checked"`
	Passed   int            `json:"passed"`
	Failed   int            `json:"failed"`
	Skipped  int            `json:"skipped"`
	Findings int            `json:"findings"`
	BySev    map[string]int `json:"by_severity"`
	BySkip   map[string]int `json:"by_skip_reason"`
}

var celEnv *cel.Env

func init() {
	env, err := cel.NewEnv(append([]cel.EnvOption{
		ext.Strings(), // lowerAscii, split, trim, replace, … on strings
		cel.Variable("obj", cel.MapType(cel.StringType, cel.DynType)),
		// attr(obj, "name") -> first value or "" (case-insensitive)
		cel.Function("attr",
			cel.Overload("attr_map_string", []*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(o, name ref.Val) ref.Val {
					return types.String(firstAttr(o, string(name.(types.String))))
				}))),
		// attrs(obj, "name") -> list of values
		cel.Function("attrs",
			cel.Overload("attrs_map_string", []*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType}, cel.ListType(cel.StringType),
				cel.BinaryBinding(func(o, name ref.Val) ref.Val {
					vals := allAttr(o, string(name.(types.String)))
					out := make([]ref.Val, len(vals))
					for i, v := range vals {
						out[i] = types.String(v)
					}
					return types.NewRefValList(types.DefaultTypeAdapter, out)
				}))),
		// intattr(obj, "name") -> first value parsed as int (0 when absent/invalid)
		cel.Function("intattr",
			cel.Overload("intattr_map_string", []*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType}, cel.IntType,
				cel.BinaryBinding(func(o, name ref.Val) ref.Val {
					n, _ := strconv.ParseInt(firstAttr(o, string(name.(types.String))), 10, 64)
					return types.Int(n)
				}))),
		// hasattr(obj, "name")
		cel.Function("hasattr",
			cel.Overload("hasattr_map_string", []*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(o, name ref.Val) ref.Val {
					return types.Bool(len(allAttr(o, string(name.(types.String)))) > 0)
				}))),
	}, helperOptions()...)...)
	if err != nil {
		panic("check: cel env: " + err.Error())
	}
	celEnv = env
}

// CompileCondition type-checks a CEL condition; the result must be bool.
func CompileCondition(expr string) (cel.Program, error) {
	ast, iss := celEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("condition must evaluate to bool, got %s", ast.OutputType())
	}
	return celEnv.Program(ast, cel.EvalOptions(cel.OptOptimize))
}

func objectToCEL(o snapshot.Object, now int64, t0 *tier0.Set) map[string]any {
	attrs := make(map[string]any, len(o.Attrs))
	for k, v := range o.Attrs {
		vals := make([]any, len(v))
		for i, s := range v {
			vals[i] = s
		}
		attrs[strings.ToLower(k)] = vals
	}
	cls := make([]any, len(o.Class))
	for i, c := range o.Class {
		cls[i] = c
	}
	m := map[string]any{"dn": o.DN, "class": cls, "attrs": attrs, "now": now, "tier0": false, "tier0_reason": "", "base": currentBase}
	if t0 != nil {
		if ok, why := t0.IsDN(o.DN); ok {
			m["tier0"], m["tier0_reason"] = true, why
		}
	}
	return m
}

func firstAttr(o ref.Val, name string) string {
	vals := allAttr(o, name)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func allAttr(o ref.Val, name string) []string {
	m, ok := o.Value().(map[string]any)
	if !ok {
		return nil
	}
	attrs, ok := m["attrs"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := attrs[strings.ToLower(name)].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// EvalOptions tunes a run.
type EvalOptions struct {
	Quick bool // run only packs marked quick: true; the rest are reported as skipped ("quick")
}

// currentTier0 is the Tier-0 set of the snapshot being evaluated, read by the
// tier0_sid and aces helpers. evalMu serialises evaluations that set it.
var (
	evalMu       sync.Mutex
	currentTier0 *tier0.Set
)

// Evaluate runs every pack against the snapshot and returns the Result.
// Packs for another provider or a higher tier than the snapshot are skipped
// with a reason — never silently dropped.
func Evaluate(snap *snapshot.Snapshot, packs []Pack) (*Result, error) {
	return EvaluateWith(snap, packs, EvalOptions{})
}

// EvaluateWith is Evaluate with options.
func EvaluateWith(snap *snapshot.Snapshot, packs []Pack, opts EvalOptions) (*Result, error) {
	evalMu.Lock()
	defer evalMu.Unlock()
	t0 := tier0.ResolveFor(snap.Meta.Provider, snap.Objects, snap.Meta.DomainSID)
	currentTier0, currentIndex, currentBase = t0, indexSnapshot(snap), snap.Meta.BaseDN
	defer func() { currentTier0, currentIndex, currentBase = nil, nil, "" }()
	now := snap.Collected.Unix()
	inv := Inventory{Objects: len(snap.Objects), Collected: snap.Collected, Identity: snap.Meta.Identity,
		Domain: snap.Meta.Domain, BaseDN: snap.Meta.BaseDN, Unresolved: t0.Unresolved, NotRead: snap.Skipped,
		Duration: snap.Meta.Duration, Searches: snap.Meta.QueryCount, Tier0: []Tier0Entry{}}
	for _, o := range snap.Objects {
		if ok, why := t0.IsDN(o.DN); ok {
			inv.Tier0 = append(inv.Tier0, Tier0Entry{DN: o.DN, Reason: why})
		}
	}
	sort.Slice(inv.Tier0, func(i, j int) bool { return inv.Tier0[i].Reason < inv.Tier0[j].Reason })

	hash, err := snapshot.Hash(snap)
	if err != nil {
		return nil, err
	}
	res := &Result{
		SnapshotHash: hash, Provider: snap.Meta.Provider, Dialect: snap.Meta.Dialect,
		Target: snap.Meta.Target, Tier: snap.Meta.Tier, AnalysedAt: time.Now().UTC(),
		Counts: Counts{BySev: map[string]int{}, BySkip: map[string]int{}}, Inventory: inv,
	}
	dialect := snap.Meta.Dialect
	if dialect == "" {
		dialect = snap.Meta.Provider
	}
	for _, p := range packs {
		start := time.Now()
		cr := CheckResult{ID: p.ID, Title: p.Title, Domain: p.Domain, Tier: p.Tier, Severity: p.Severity, Signed: p.Signed,
			Attack: p.Attack, Remediation: p.Remediation, References: p.References}
		if !p.Signed {
			res.Unsigned = true
		}
		switch {
		case opts.Quick && !p.Quick:
			cr.Status, cr.Skip = "skipped", "quick"
		case !contains(p.Provider, dialect) && !contains(p.Provider, snap.Meta.Provider):
			cr.Status, cr.Skip = "skipped", "provider"
		case p.Tier > snap.Meta.Tier:
			cr.Status, cr.Skip = "skipped", "tier"
		default:
			if err := runPack(snap, &p, &cr, now, t0); err != nil {
				cr.Status, cr.Skip = "skipped", "error"
				cr.Findings = nil
				cr.Evidence(err)
			}
		}
		cr.Duration = time.Since(start).Round(time.Microsecond).String()
		res.Checks = append(res.Checks, cr)
		tally(res, cr)
	}
	res.Score = score(res)
	return res, nil
}

// Evidence attaches an evaluation error as a pseudo-finding so it is visible.
func (cr *CheckResult) Evidence(err error) {
	cr.Findings = append(cr.Findings, Finding{CheckID: cr.ID, Severity: "info", DN: "", Evidence: map[string]string{"error": err.Error()}})
}

func runPack(snap *snapshot.Snapshot, p *Pack, cr *CheckResult, now int64, t0 *tier0.Set) error {
	// <default> in a pack filter stands for the snapshot's base DN, so packs
	// can name containers (memberOf=cn=admins,…,<default>) without hard-coding a domain.
	filter, err := ParseFilter(strings.ReplaceAll(p.Query.Filter, "<default>", snap.Meta.BaseDN))
	if err != nil {
		return err
	}
	prog, err := CompileCondition(p.Condition)
	if err != nil {
		return err
	}
	for _, o := range snap.Objects {
		if !filter.Match(o) {
			continue
		}
		cr.Matched++
		obj := objectToCEL(o, now, t0)
		out, _, err := prog.Eval(map[string]any{"obj": obj})
		if err != nil {
			return fmt.Errorf("evaluating %s on %s: %w", p.ID, o.DN, err)
		}
		if b, ok := out.Value().(bool); ok && b {
			f := Finding{CheckID: p.ID, Severity: p.Severity, DN: o.DN, Evidence: map[string]string{}}
			for _, a := range p.Evidence {
				f.Evidence[a] = strings.Join(values(o, a), "; ")
			}
			if why, _ := obj["tier0_reason"].(string); why != "" {
				f.Evidence["tier0"] = why
			}
			cr.Findings = append(cr.Findings, f)
		}
	}
	if len(cr.Findings) > 0 {
		cr.Status = "fail"
	} else if cr.Matched == 0 && notCollected(snap, p.Query.Filter) {
		// The objects this check looks at were not collected (no permission,
		// absent container): say so instead of reporting a pass (AR-12).
		cr.Status, cr.Skip = "skipped", "not-collected"
	} else {
		cr.Status = "pass"
	}
	return nil
}

var objectClassRe = regexp.MustCompile(`(?i)objectclass=([A-Za-z0-9_-]+)`)

// notCollected reports whether a collection query that would have returned the
// object classes named in filter was skipped by the collector.
func notCollected(snap *snapshot.Snapshot, filter string) bool {
	classes := map[string]bool{}
	for _, m := range objectClassRe.FindAllStringSubmatch(filter, -1) {
		classes[strings.ToLower(m[1])] = true
	}
	if len(classes) == 0 {
		return false
	}
	for _, sk := range snap.Skipped {
		for _, c := range sk.Classes {
			if classes[strings.ToLower(c)] {
				return true
			}
		}
	}
	return false
}

func tally(res *Result, cr CheckResult) {
	switch cr.Status {
	case "pass":
		res.Counts.Checked++
		res.Counts.Passed++
	case "fail":
		res.Counts.Checked++
		res.Counts.Failed++
		res.Counts.Findings += len(cr.Findings)
		res.Counts.BySev[cr.Severity] += len(cr.Findings)
	case "skipped":
		res.Counts.Skipped++
		res.Counts.BySkip[cr.Skip]++
	}
}

// score is a placeholder model: start at 100, subtract per failed check by
// severity, floor at 0. The real model is designed before v1.0 (approach §8)
// and documented in docs/scoring.md; this one exists so the report has a number.
func score(res *Result) int {
	weights := map[string]int{"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
	s := 100
	for _, c := range res.Checks {
		if c.Status == "fail" {
			s -= weights[c.Severity]
		}
	}
	if s < 0 {
		s = 0
	}
	return s
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// SortedSeverities returns severities present in counts, most severe first.
func SortedSeverities(c Counts) []string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var out []string
	for _, s := range order {
		if c.BySev[s] > 0 {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return false })
	return out
}
