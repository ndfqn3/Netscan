package portscan

import "testing"

func TestTargetsTmp(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"192.168.1.1/32", 1},
		{"192.168.1.0/30", 2},
		{"192.168.1.1-10", 10},
	}
	for _, c := range cases {
		got, err := parseTargets([]string{c.in}, 10000)
		if err != nil {
			t.Fatalf("%s: 错误 %v", c.in, err)
		}
		if len(got) != c.want {
			t.Fatalf("%s: 期望 %d, 得到 %d (%v)", c.in, c.want, len(got), got)
		}
	}
	if _, err := parseTargets([]string{"192.168.1.1-300"}, 10000); err == nil {
		t.Fatalf("192.168.1.1-300 应该报越界错误")
	}
}
