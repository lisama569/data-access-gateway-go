package masking

import (
	"strings"
	"testing"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestMaskIsIrreversible(t *testing.T) {
	value := "alice@example.com"
	got := maskValue(value, 1, 4)
	if got == value || strings.Contains(got, "alice@example") {
		t.Fatalf("masked value leaks original content: %q", got)
	}
	if got != "a************.com" {
		t.Fatalf("unexpected mask output: %q", got)
	}
	// Over-large keep windows must collapse to full redaction.
	if got := maskValue("ab", 1, 1); got != redactionMarker {
		t.Fatalf("expected full redaction, got %q", got)
	}
}

func TestApplierTransformsAndCoversEveryField(t *testing.T) {
	reg := NewRegistry()
	profile := model.MaskingProfile{Name: "p", Rules: []model.FieldRule{
		{Field: "email", Transform: model.TransformMask, KeepPrefix: 1, KeepSuffix: 3},
		{Field: "phone", Transform: model.TransformRedact},
	}}
	if err := reg.Register(profile); err != nil {
		t.Fatal(err)
	}
	a, err := NewApplier(reg, "p", []string{"email", "phone"})
	if err != nil {
		t.Fatal(err)
	}
	out, fields, err := a.Apply(map[string]string{"email": "bob@example.com", "phone": "12345"})
	if err != nil {
		t.Fatal(err)
	}
	if out["phone"] != "***" {
		t.Fatalf("redact mismatch: %q", out["phone"])
	}
	if out["email"] == "bob@example.com" {
		t.Fatalf("email was not masked")
	}
	if len(fields) != 2 {
		t.Fatalf("expected 2 transformed fields, got %v", fields)
	}

	// Missing coverage for a requested field is rejected, never downgraded.
	if _, err := NewApplier(reg, "p", []string{"email", "ssn"}); err != ErrFieldNotCovered {
		t.Fatalf("expected ErrFieldNotCovered, got %v", err)
	}
	// Unknown profile name is rejected.
	if _, err := NewApplier(reg, "nope", []string{"email"}); err != ErrProfileNotFound {
		t.Fatalf("expected ErrProfileNotFound, got %v", err)
	}
}

func TestInvalidProfilesRejected(t *testing.T) {
	reg := NewRegistry()
	cases := map[string]model.MaskingProfile{
		"empty name":         {Rules: []model.FieldRule{{Field: "x", Transform: model.TransformRedact}}},
		"unknown transform":  {Name: "a", Rules: []model.FieldRule{{Field: "x", Transform: "bogus"}}},
		"tokenize no domain": {Name: "b", Rules: []model.FieldRule{{Field: "x", Transform: model.TransformTokenize}}},
		"negative keep":      {Name: "c", Rules: []model.FieldRule{{Field: "x", Transform: model.TransformMask, KeepPrefix: -1}}},
		"duplicate field rule": {Name: "d", Rules: []model.FieldRule{
			{Field: "x", Transform: model.TransformRedact},
			{Field: "x", Transform: model.TransformMask},
		}},
	}
	for name, p := range cases {
		if err := reg.Register(p); err == nil {
			t.Fatalf("%s: expected registration to fail", name)
		}
	}
}

func TestTokenStableWithinDomainIsolatedAcrossDomains(t *testing.T) {
	v := NewVault([]byte("test-seed"))
	value := "alice@example.com"

	tokA1 := v.Tokenize("crm", value)
	tokA2 := v.Tokenize("crm", value)
	tokB := v.Tokenize("billing", value)

	if tokA1 != tokA2 {
		t.Fatalf("tokens not stable within domain: %q vs %q", tokA1, tokA2)
	}
	if tokA1 == tokB {
		t.Fatalf("token leaked across domains: %q", tokA1)
	}
	if !strings.HasPrefix(tokA1, "tok_") {
		t.Fatalf("token marker missing: %q", tokA1)
	}

	// Reversible only inside the minting domain.
	back, err := v.Detokenize("crm", tokA1)
	if err != nil || back != value {
		t.Fatalf("in-domain detokenize failed: %q %v", back, err)
	}
	if _, err := v.Detokenize("billing", tokA1); err != ErrTokenUnknown {
		t.Fatalf("cross-domain detokenize must fail, got %v", err)
	}

	// A second vault with the same seed reproduces tokens; with another seed
	// it produces unrelated tokens that the first vault cannot reverse.
	rep := NewVault([]byte("test-seed"))
	if rep.Tokenize("crm", value) != tokA1 {
		t.Fatalf("same seed/domain/value must reproduce the same token")
	}
	other := NewVault([]byte("different-seed"))
	foreign := other.Tokenize("crm", value)
	if foreign == tokA1 {
		t.Fatalf("different seed unexpectedly produced identical token")
	}
	if _, err := v.Detokenize("crm", foreign); err != ErrTokenUnknown {
		t.Fatalf("foreign-domain token must not reverse in this vault, got %v", err)
	}
}
