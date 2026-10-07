package payloads

import (
	"os"
	"strings"
	"testing"
)

func TestLists(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no builtin payload lists")
	}
	for _, n := range names {
		lines, err := Lines(n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if len(lines) == 0 {
			t.Fatalf("%s: empty list", n)
		}
		seen := map[string]bool{}
		for _, ln := range lines {
			if len(ln) > 4096 {
				t.Fatalf("%s: line too long (%d bytes)", n, len(ln))
			}
			if strings.ContainsRune(ln, 0) {
				t.Fatalf("%s: NUL byte in line", n)
			}
			if seen[ln] {
				t.Fatalf("%s: duplicated line %q", n, ln)
			}
			seen[ln] = true
		}
	}
}

func TestResolveAndMaterialize(t *testing.T) {
	if _, err := Lines("springboot_actuator"); err != nil {
		t.Fatalf("basename resolve: %v", err)
	}
	p, err := Materialize("springboot_actuator")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := Lines("no-such-list-xyz"); err == nil {
		t.Fatal("expected error for unknown list")
	}
}
