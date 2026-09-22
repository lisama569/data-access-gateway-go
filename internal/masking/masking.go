// Package masking implements field-level irreversible redaction and masking
// plus reversible, domain-scoped deterministic tokenization.
//
// Guarantees:
//   - redact/mask outputs never carry enough information to reconstruct the
//     original value;
//   - tokenize outputs are stable and reversible only inside the token domain
//     in which they were minted (domain-separated HMAC under a per-domain key
//     derived from the master seed); the same value in a different domain
//     yields a different token that cannot be reversed in the other domain;
//   - missing or malformed masking configuration is rejected explicitly; it is
//     never silently downgraded to a weaker transform or to plaintext.
package masking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// defaultDevSeed is a fixed, non-secret seed for fully local, reproducible
// test/demo runs. Production code injects its own seed via NewRegistryWithSeed.
var defaultDevSeed = []byte("local-data-access-gateway-dev-seed-v1")

var (
	// ErrProfileNotFound indicates the named masking profile is not registered.
	ErrProfileNotFound = errors.New("masking: profile not found")
	// ErrDuplicateFieldRule indicates a profile lists the same field twice.
	ErrDuplicateFieldRule = errors.New("masking: duplicate field rule in profile")
	// ErrUnknownTransform indicates a rule uses an unsupported transform.
	ErrUnknownTransform = errors.New("masking: unknown transform")
	// ErrMissingTokenDomain indicates a tokenize rule has no domain.
	ErrMissingTokenDomain = errors.New("masking: tokenize rule requires a token domain")
	// ErrNegativeKeep indicates mask keep counts are negative.
	ErrNegativeKeep = errors.New("masking: negative keep prefix/suffix")
	// ErrFieldNotCovered indicates the profile does not configure a required
	// field: no silent downgrade is permitted.
	ErrFieldNotCovered = errors.New("masking: profile does not cover required field")
	// ErrEmptyProfileName indicates registration under an empty name.
	ErrEmptyProfileName = errors.New("masking: empty profile name")
)

// redactionMarker is the fixed, context-free output of the redact transform.
const redactionMarker = "***"

// Vault mints and reverses domain-scoped tokens. It is safe for concurrent use.
type Vault struct {
	mu   sync.RWMutex
	seed []byte
	// tables[domain][token] = plaintext. A token is reversible only by the
	// domain table that minted it.
	tables map[string]map[string]string
}

// NewVault creates a token vault bound to masterSeed.
func NewVault(masterSeed []byte) *Vault {
	seed := append([]byte(nil), masterSeed...)
	return &Vault{seed: seed, tables: make(map[string]map[string]string)}
}

// domainKey derives a per-domain key via HKDF-SHA256 (RFC 5869) so domains
// are cryptographically separated. It uses only the standard library.
func (v *Vault) domainKey(domain string) []byte {
	info := []byte("token-domain:" + domain)
	const hashLen = sha256.Size

	// Extract: PRK = HMAC(salt, IKM); salt defaults to a zero-length block.
	salt := make([]byte, hashLen)
	extract := hmac.New(sha256.New, salt)
	extract.Write(v.seed)
	prk := extract.Sum(nil)

	// Expand: OKM = T(1) for a single 32-byte block (L <= hashLen).
	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:32]
}

// Tokenize returns the stable token for value inside domain. The same
// (domain, value) pair always maps to the same token; two domains never share
// a token for the same value.
func (v *Vault) Tokenize(domain, value string) string {
	mac := hmac.New(sha256.New, v.domainKey(domain))
	mac.Write([]byte(value))
	token := "tok_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	v.mu.Lock()
	defer v.mu.Unlock()
	tbl, ok := v.tables[domain]
	if !ok {
		tbl = make(map[string]string)
		v.tables[domain] = tbl
	}
	// Determinism means any prior entry is the same plaintext.
	tbl[token] = value
	return token
}

// Detokenize reverses token only within domain. A token minted by another
// domain is never resolvable here.
func (v *Vault) Detokenize(domain, token string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	tbl, ok := v.tables[domain]
	if !ok {
		return "", ErrTokenUnknown
	}
	value, ok := tbl[token]
	if !ok {
		return "", ErrTokenUnknown
	}
	return value, nil
}

// ErrTokenUnknown indicates the token was not minted in the given domain.
var ErrTokenUnknown = errors.New("masking: token unknown in domain")

// Registry holds named, validated masking profiles and the shared token vault.
type Registry struct {
	mu       sync.RWMutex
	profiles map[string]model.MaskingProfile
	vault    *Vault
}

// NewRegistry returns a registry seeded with the fixed local development seed.
func NewRegistry() *Registry { return NewRegistryWithSeed(defaultDevSeed) }

// NewRegistryWithSeed returns a registry with an explicit master seed.
func NewRegistryWithSeed(masterSeed []byte) *Registry {
	return &Registry{
		profiles: make(map[string]model.MaskingProfile),
		vault:    NewVault(masterSeed),
	}
}

// Vault exposes the shared token vault.
func (r *Registry) Vault() *Vault { return r.vault }

// validateProfile checks a profile's internal consistency.
func validateProfile(p model.MaskingProfile) error {
	if p.Name == "" {
		return ErrEmptyProfileName
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for _, rule := range p.Rules {
		if rule.Field == "" {
			return ErrFieldNotCovered
		}
		if _, dup := seen[rule.Field]; dup {
			return ErrDuplicateFieldRule
		}
		seen[rule.Field] = struct{}{}
		switch rule.Transform {
		case model.TransformRedact, model.TransformMask:
			// ok
		case model.TransformTokenize:
			if rule.TokenDomain == "" {
				return ErrMissingTokenDomain
			}
		default:
			return ErrUnknownTransform
		}
		if rule.KeepPrefix < 0 || rule.KeepSuffix < 0 {
			return ErrNegativeKeep
		}
	}
	return nil
}

// Register validates and stores a profile. The profile is copied first.
func (r *Registry) Register(p model.MaskingProfile) error {
	if err := validateProfile(p); err != nil {
		return err
	}
	cp := model.MaskingProfile{Name: p.Name, Rules: append([]model.FieldRule(nil), p.Rules...)}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[p.Name] = cp
	return nil
}

// Get returns a registered profile.
func (r *Registry) Get(name string) (model.MaskingProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[name]
	if !ok {
		return model.MaskingProfile{}, false
	}
	p.Rules = append([]model.FieldRule(nil), p.Rules...)
	return p, ok
}

// maskValue irreversibly masks value: KeepPrefix head and KeepSuffix tail are
// preserved and the middle is replaced by '*'. When the preserved windows
// would reveal the entire value, the value is fully redacted instead.
func maskValue(value string, keepPrefix, keepSuffix int) string {
	n := len(value)
	if n == 0 {
		return ""
	}
	if keepPrefix+keepSuffix >= n {
		return redactionMarker
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if i < keepPrefix || i >= n-keepSuffix {
			out[i] = value[i]
		} else {
			out[i] = '*'
		}
	}
	return string(out)
}

// Applier applies one validated profile covering a fixed set of fields.
type Applier struct {
	rules  map[string]model.FieldRule
	fields []string
	vault  *Vault
}

// NewApplier builds an Applier for profileName covering exactly fields. Every
// field must have a rule in the profile, the profile must exist and be valid;
// otherwise an error is returned instead of silently leaking plaintext.
func NewApplier(reg *Registry, profileName string, fields []string) (*Applier, error) {
	profile, ok := reg.Get(profileName)
	if !ok {
		return nil, ErrProfileNotFound
	}
	rules := make(map[string]model.FieldRule, len(profile.Rules))
	for _, rule := range profile.Rules {
		rules[rule.Field] = rule
	}
	covered := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, ok := rules[f]; !ok {
			return nil, ErrFieldNotCovered
		}
		covered = append(covered, f)
	}
	return &Applier{rules: rules, fields: covered, vault: reg.Vault()}, nil
}

// Fields returns the field set the applier is authorized to transform.
func (a *Applier) Fields() []string { return append([]string(nil), a.fields...) }

// Apply transforms every covered value. It never returns an original value
// untransformed. transformed lists the fields that were masked/tokenized.
func (a *Applier) Apply(in map[string]string) (out map[string]string, transformed []string, err error) {
	out = make(map[string]string, len(in))
	for field, value := range in {
		rule, ok := a.rules[field]
		if !ok {
			// Untransformed output for a covered record is forbidden.
			return nil, nil, ErrFieldNotCovered
		}
		switch rule.Transform {
		case model.TransformRedact:
			if value != "" {
				out[field] = redactionMarker
			} else {
				out[field] = ""
			}
		case model.TransformMask:
			out[field] = maskValue(value, rule.KeepPrefix, rule.KeepSuffix)
		case model.TransformTokenize:
			out[field] = a.vault.Tokenize(rule.TokenDomain, value)
		default:
			return nil, nil, ErrUnknownTransform
		}
		transformed = append(transformed, field)
	}
	return out, transformed, nil
}
