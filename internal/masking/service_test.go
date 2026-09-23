package masking

import (
	"strings"
	"testing"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func sampleRecord() *model.Record {
	return &model.Record{
		ID:       "r1",
		Resource: "patient:1",
		Fields:   map[string]string{"name": "Alice Chen", "ssn": "123-45-6789", "city": "Shanghai"},
	}
}

func TestMaskIsIrreversible(t *testing.T) {
	s := NewService()
	out, changed, err := s.Apply(sampleRecord(), []model.FieldRule{{Field: "name", Transform: "mask"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Fields["name"] == "Alice Chen" || strings.Contains(out.Fields["name"], "Alice") {
		t.Fatalf("masked value leaks original: %q", out.Fields["name"])
	}
	if out.Fields["name"] != redactedMarker {
		t.Fatalf("unexpected masked value %q", out.Fields["name"])
	}
	if len(changed) != 1 || changed[0] != "name" {
		t.Fatalf("changed = %v", changed)
	}
	// 原始记录不得被修改。
	if sampleRecord().Fields["name"] != "Alice Chen" {
		t.Fatal("source record mutated")
	}
}

func TestTokenizeStableWithinDomainAndReversible(t *testing.T) {
	s := NewService()
	rules := []model.FieldRule{{Field: "ssn", Transform: "tokenize", TokenDomain: "hr"}}
	out1, _, err := s.Apply(sampleRecord(), rules)
	if err != nil {
		t.Fatal(err)
	}
	out2, _, err := s.Apply(sampleRecord(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if out1.Fields["ssn"] != out2.Fields["ssn"] {
		t.Fatalf("token not stable: %q vs %q", out1.Fields["ssn"], out2.Fields["ssn"])
	}
	if strings.Contains(out1.Fields["ssn"], "123") {
		t.Fatal("token must not reveal original")
	}
	plain, ok := s.Detokenize("hr", out1.Fields["ssn"])
	if !ok || plain != "123-45-6789" {
		t.Fatalf("same-domain detokenize failed: %q %v", plain, ok)
	}
}

func TestTokenDomainsAreIsolated(t *testing.T) {
	s := NewService()
	t1, err := s.DomainToken("domain-a", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DomainToken("domain-b", "secret"); err != nil {
		t.Fatal(err)
	}
	// A 域令牌无法在 B 域还原。
	if _, ok := s.Detokenize("domain-b", t1); ok {
		t.Fatal("cross-domain detokenize must fail")
	}
	if _, ok := s.Detokenize("nonexistent", t1); ok {
		t.Fatal("unknown domain detokenize must fail")
	}
	// 不同域对相同原文产生不同令牌。
	tb, _ := s.DomainToken("domain-b", "secret")
	if t1 == tb {
		t.Fatal("tokens from different domains must differ")
	}
}

func TestInvalidMaskingConfigRejected(t *testing.T) {
	s := NewService()
	cases := [][]model.FieldRule{
		{{Field: "", Transform: "mask"}},
		{{Field: "x", Transform: "bogus"}},
		{{Field: "x", Transform: "tokenize", TokenDomain: ""}},
		{{Field: "x", Transform: "mask"}, {Field: "x", Transform: "mask"}},
	}
	for i, rules := range cases {
		if err := s.Validate(rules); err == nil {
			t.Fatalf("case %d must be invalid", i)
		}
		if _, _, err := s.Apply(sampleRecord(), rules); err == nil {
			t.Fatalf("case %d apply must fail instead of silent downgrade", i)
		}
	}
	// 规则指向不存在的字段也必须拒绝。
	if _, _, err := s.Apply(sampleRecord(), []model.FieldRule{{Field: "ghost", Transform: "mask"}}); err == nil {
		t.Fatal("rule on missing field must be rejected")
	}
}
