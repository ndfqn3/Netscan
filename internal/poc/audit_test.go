package poc

import (
	"strconv"
	"testing"
)

func TestJSONPathSimple(t *testing.T) {
	data := `{"a":{"b":1},"c":["x","y"],"d":[{"e":"z"}],"n":null,"f":1.5,"ok":true}`
	cases := map[string]string{
		".a.b":     "1",
		"a.b":      "1",
		"c[1]":     "y",
		"d[0].e":   "z",
		"c[9]":     "",
		"missing":  "",
		"$.c[0]":   "x",
		"n":        "",
		"f":        "1.5",
		"ok":       "true",
		"d[0]":     `{"e":"z"}`,
		"a":        `{"b":1}`,
		"c":        `["x","y"]`,
		"a.b.c.d":  "",
		"c[0].x.y": "",
	}
	for p, want := range cases {
		if got := jsonPathSimple(data, p); got != want {
			t.Fatalf("%s: want %q got %q", p, want, got)
		}
	}
	if got := jsonPathSimple("not-json", "a"); got != "" {
		t.Fatalf("invalid json should be empty, got %q", got)
	}
}

func TestBuiltinPOCList(t *testing.T) {
	all := BuiltinPOCList("", 0)
	if len(all) < 5000 {
		t.Fatalf("内置模板数量异常: %d", len(all))
	}
	if got := BuiltinPOCList("CVE-2021-41773", 5); len(got) == 0 {
		t.Fatal("按 CVE 过滤无结果")
	}
}

func TestRandHelperBounds(t *testing.T) {
	v, ok := evalHelper("rand_int(-5,5)")
	if !ok {
		t.Fatal("rand_int failed")
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < -5 || n > 5 {
		t.Fatalf("bad rand_int: %s", v)
	}
	// 极端跨度不得 panic(旧的 b-a+1 会整数溢出)
	if v, ok := evalHelper("rand_int(-9223372036854775808,9223372036854775807)"); !ok {
		t.Fatal("extreme rand_int failed")
	} else if _, err := strconv.ParseInt(v, 10, 64); err != nil {
		t.Fatalf("extreme rand_int invalid: %q", v)
	}
	s, _ := evalHelper("rand_text_alpha(100000)")
	if len(s) > 4096 {
		t.Fatalf("长度上限未生效: %d", len(s))
	}
}
