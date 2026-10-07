package check

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/atsvetko/directory-auditor/internal/snapshot"
)

// Filter is a parsed RFC 4515 search filter, re-applied to snapshot objects so
// that analysis never needs the live directory. Supported: and, or, not,
// equality, presence, substring, >=, <=, and the Active Directory bitwise
// matching rules LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803) and
// LDAP_MATCHING_RULE_BIT_OR (1.2.840.113556.1.4.804).
type Filter interface {
	Match(o snapshot.Object) bool
	String() string
}

type and struct{ kids []Filter }
type or struct{ kids []Filter }
type not struct{ kid Filter }
type cmp struct {
	attr, op, val string // op: = >= <= present substr bitand bitor
	parts         []string
}

func (f and) Match(o snapshot.Object) bool {
	for _, k := range f.kids {
		if !k.Match(o) {
			return false
		}
	}
	return true
}
func (f or) Match(o snapshot.Object) bool {
	for _, k := range f.kids {
		if k.Match(o) {
			return true
		}
	}
	return false
}
func (f not) Match(o snapshot.Object) bool { return !f.kid.Match(o) }

func (f cmp) Match(o snapshot.Object) bool {
	vals := values(o, f.attr)
	switch f.op {
	case "present":
		return len(vals) > 0
	case "=":
		for _, v := range vals {
			if strings.EqualFold(v, f.val) {
				return true
			}
		}
		return false
	case "substr":
		for _, v := range vals {
			if substrMatch(strings.ToLower(v), f.parts) {
				return true
			}
		}
		return false
	case ">=", "<=":
		want, err := strconv.ParseInt(f.val, 10, 64)
		if err != nil {
			for _, v := range vals {
				if (f.op == ">=" && v >= f.val) || (f.op == "<=" && v <= f.val) {
					return true
				}
			}
			return false
		}
		for _, v := range vals {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if (f.op == ">=" && n >= want) || (f.op == "<=" && n <= want) {
				return true
			}
		}
		return false
	case "bitand", "bitor":
		mask, err := strconv.ParseInt(f.val, 10, 64)
		if err != nil {
			return false
		}
		for _, v := range vals {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			if f.op == "bitand" && n&mask == mask {
				return true
			}
			if f.op == "bitor" && n&mask != 0 {
				return true
			}
		}
		return false
	}
	return false
}

func (f and) String() string { return "(&" + join(f.kids) + ")" }
func (f or) String() string  { return "(|" + join(f.kids) + ")" }
func (f not) String() string { return "(!" + f.kid.String() + ")" }
func (f cmp) String() string {
	switch f.op {
	case "present":
		return "(" + f.attr + "=*)"
	case "substr":
		return "(" + f.attr + "=" + strings.Join(f.parts, "*") + ")"
	case "bitand":
		return "(" + f.attr + ":1.2.840.113556.1.4.803:=" + f.val + ")"
	case "bitor":
		return "(" + f.attr + ":1.2.840.113556.1.4.804:=" + f.val + ")"
	}
	return "(" + f.attr + f.op + f.val + ")"
}

func join(ks []Filter) string {
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k.String())
	}
	return b.String()
}

func values(o snapshot.Object, attr string) []string {
	if strings.EqualFold(attr, "objectClass") && len(o.Class) > 0 {
		return o.Class
	}
	for k, v := range o.Attrs {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

// substrMatch implements LDAP substring semantics: parts[0] is the initial
// (may be empty), parts[len-1] the final (may be empty), the rest are "any".
func substrMatch(v string, parts []string) bool {
	if len(parts) == 0 {
		return true
	}
	if parts[0] != "" {
		if !strings.HasPrefix(v, parts[0]) {
			return false
		}
		v = v[len(parts[0]):]
	}
	last := len(parts) - 1
	for i := 1; i < last; i++ {
		idx := strings.Index(v, parts[i])
		if idx < 0 {
			return false
		}
		v = v[idx+len(parts[i]):]
	}
	if last > 0 && parts[last] != "" {
		return strings.HasSuffix(v, parts[last])
	}
	return true
}

// ParseFilter parses an RFC 4515 filter string.
func ParseFilter(s string) (Filter, error) {
	p := &parser{s: strings.TrimSpace(s)}
	f, err := p.parse()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("filter: trailing data at %d", p.pos)
	}
	return f, nil
}

type parser struct {
	s   string
	pos int
}

func (p *parser) parse() (Filter, error) {
	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		return nil, fmt.Errorf("filter: expected '(' at %d", p.pos)
	}
	p.pos++
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("filter: unexpected end")
	}
	switch p.s[p.pos] {
	case '&', '|':
		op := p.s[p.pos]
		p.pos++
		var kids []Filter
		for p.pos < len(p.s) && p.s[p.pos] == '(' {
			k, err := p.parse()
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("filter: empty %c list", op)
		}
		if op == '&' {
			return and{kids}, nil
		}
		return or{kids}, nil
	case '!':
		p.pos++
		k, err := p.parse()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		return not{k}, nil
	}
	end := strings.IndexByte(p.s[p.pos:], ')')
	if end < 0 {
		return nil, fmt.Errorf("filter: missing ')' after %d", p.pos)
	}
	item := p.s[p.pos : p.pos+end]
	p.pos += end + 1
	return parseItem(item)
}

func (p *parser) expect(c byte) error {
	if p.pos >= len(p.s) || p.s[p.pos] != c {
		return fmt.Errorf("filter: expected '%c' at %d", c, p.pos)
	}
	p.pos++
	return nil
}

func parseItem(item string) (Filter, error) {
	for _, op := range []string{">=", "<=", ":="} {
		if i := strings.Index(item, op); i > 0 {
			attr, val := item[:i], unescape(item[i+2:])
			if op == ":=" {
				// Extensible match of the form attr:rule:=value (no :dn: variants).
				segs := strings.Split(attr, ":")
				if len(segs) != 2 || segs[0] == "" {
					return nil, fmt.Errorf("filter: unsupported extensible match %q", item)
				}
				switch segs[1] {
				case "1.2.840.113556.1.4.803":
					return cmp{attr: segs[0], op: "bitand", val: val}, nil
				case "1.2.840.113556.1.4.804":
					return cmp{attr: segs[0], op: "bitor", val: val}, nil
				}
				return nil, fmt.Errorf("filter: unsupported matching rule in %q", item)
			}
			return cmp{attr: attr, op: op, val: val}, nil
		}
	}
	i := strings.IndexByte(item, '=')
	if i <= 0 {
		return nil, fmt.Errorf("filter: bad item %q", item)
	}
	attr, val := item[:i], item[i+1:]
	if val == "*" {
		return cmp{attr: attr, op: "present"}, nil
	}
	if strings.Contains(val, "*") {
		raw := strings.Split(val, "*")
		parts := make([]string, len(raw))
		for j, r := range raw {
			parts[j] = strings.ToLower(unescape(r))
		}
		return cmp{attr: attr, op: "substr", parts: parts}, nil
	}
	return cmp{attr: attr, op: "=", val: unescape(val)}, nil
}

// unescape handles RFC 4515 \xx escapes.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
