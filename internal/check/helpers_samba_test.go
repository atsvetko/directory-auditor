package check

import "testing"

func TestVersionAndIntHelpers(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`version_lt("4.17.3", "4.17.4")`, true},
		{`version_lt("4.17.4", "4.17.4")`, false},
		{`version_lt("4.19.9-Debian", "4.23.0")`, true},
		{`version_lt("4.25", "4.23.0")`, false},
		{`version_lt("", "4.23.0")`, false},
		{`version_lt("unknown", "4.23.0")`, false},
		{`intval("0x1c") == 28 && mask_has(intval("0x1c"), 4)`, true},
		{`intval("24") == 24 && !mask_has(intval("24"), 4)`, true},
		{`intval("aes256-cts") == 0`, true},
		{`smbbool(obj, "server schannel", true) && !smbbool(obj, "allow nt4 crypto", false) && smbbool(obj, "absent", true)`, true},
	}
	obj := map[string]any{"dn": "x", "class": []any{}, "attrs": map[string]any{"server schannel": []any{"Yes"}, "allow nt4 crypto": []any{"No"}}}
	for _, c := range cases {
		prog, err := CompileCondition(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		out, _, err := prog.Eval(map[string]any{"obj": obj})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if out.Value() != c.want {
			t.Errorf("%s = %v, want %v", c.expr, out.Value(), c.want)
		}
	}
}
