// Package masking 提供字段级遮蔽（不可逆）与可逆令牌化。
//
// 语义：
//   - mask（遮蔽）：任何非空值一律替换为固定常量 redactedMarker，不含长度、
//     前缀等任何原文信息，数学上不可逆；空值保持空。
//   - tokenize（令牌化）：令牌 = HMAC-SHA256(域密钥, "v1:"+原文) 的 URL 安全
//     base64 编码。每个令牌域拥有独立随机域密钥与独立保险库(vault)：
//     同域内相同原文恒定得到相同令牌且可经 Detokenize 还原；不同域密钥不同、
//     保险库隔离，A 域令牌无法在 B 域还原，也无法推出 B 域令牌。
//   - 非法或缺失的脱敏配置（未知变换类型、令牌化缺少域、字段名为空、字段重复）
//     一律由 Validate 报错，Apply 拒绝执行，绝不静默降级。
package masking

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// redactedMarker 固定遮蔽常量：不含任何原文特征。
const redactedMarker = "***REDACTED***"

const tokenPrefix = "tok_"

var (
	// ErrInvalidRule 脱敏配置非法。
	ErrInvalidRule = errors.New("invalid masking rule")
)

type domainVault struct {
	key    []byte            // 域专用 32 字节随机密钥
	tokens map[string]string // token -> 原文（还原保险库）
}

// Service 脱敏与令牌化服务，令牌域相互隔离，并发安全。
type Service struct {
	mu      sync.RWMutex
	domains map[string]*domainVault
}

// NewService 创建脱敏服务。
func NewService() *Service {
	return &Service{domains: make(map[string]*domainVault)}
}

// getOrCreateDomain 在写锁下惰性创建令牌域。
func (s *Service) getOrCreateDomain(name string) (*domainVault, error) {
	if dv, ok := s.domains[name]; ok {
		return dv, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate domain key: %w", err)
	}
	dv := &domainVault{key: key, tokens: make(map[string]string)}
	s.domains[name] = dv
	return dv, nil
}

// Validate 校验字段规则集合：非法/缺失配置必须报错而非静默降级。
func (s *Service) Validate(rules []model.FieldRule) error {
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if r.Field == "" {
			return fmt.Errorf("%w: rule[%d] has empty field", ErrInvalidRule, i)
		}
		if seen[r.Field] {
			return fmt.Errorf("%w: duplicate field %q", ErrInvalidRule, r.Field)
		}
		seen[r.Field] = true
		switch r.Transform {
		case "mask":
			// 遮蔽不需要域。
		case "tokenize":
			if r.TokenDomain == "" {
				return fmt.Errorf("%w: field %q tokenize requires token domain", ErrInvalidRule, r.Field)
			}
		default:
			return fmt.Errorf("%w: field %q unknown transform %q", ErrInvalidRule, r.Field, r.Transform)
		}
	}
	return nil
}

// computeToken 计算令牌（确定性，不修改 vault）。
func computeToken(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v1:" + value))
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Apply 按规则对记录做变换，返回输出副本、被变换字段列表。
// 原始记录不被修改；调用方负责确保 rules 通过 Validate，否则返回错误。
func (s *Service) Apply(rec *model.Record, rules []model.FieldRule) (*model.Record, []string, error) {
	if rec == nil {
		return nil, nil, errors.New("apply masking on nil record")
	}
	if err := s.Validate(rules); err != nil {
		return nil, nil, err
	}
	out := &model.Record{
		ID:          rec.ID,
		Resource:    rec.Resource,
		Sensitivity: rec.Sensitivity,
		ExpiresAt:   rec.ExpiresAt,
		Fields:      make(map[string]string, len(rec.Fields)),
	}
	for k, v := range rec.Fields {
		out.Fields[k] = v
	}
	changed := make([]string, 0, len(rules))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rules {
		v, ok := out.Fields[r.Field]
		if !ok {
			// 规则指向不存在的字段属于配置错误，不静默跳过。
			return nil, nil, fmt.Errorf("%w: field %q not present in record", ErrInvalidRule, r.Field)
		}
		switch r.Transform {
		case "mask":
			if v != "" {
				out.Fields[r.Field] = redactedMarker
			}
		case "tokenize":
			dv, err := s.getOrCreateDomain(r.TokenDomain)
			if err != nil {
				return nil, nil, err
			}
			tok := computeToken(dv.key, v)
			// 同值同令牌；保险库中登记 token->原文（HMAC 抗碰撞保证不冲突）。
			if existing, ok := dv.tokens[tok]; ok && existing != v {
				return nil, nil, errors.New("token collision (should not happen with HMAC-SHA256)")
			}
			dv.tokens[tok] = v
			out.Fields[r.Field] = tok
		}
		changed = append(changed, r.Field)
	}
	return out, changed, nil
}

// Detokenize 在指定令牌域内还原令牌；跨域或未知令牌返回 false。
func (s *Service) Detokenize(domain, token string) (string, bool) {
	if domain == "" || token == "" {
		return "", false
	}
	s.mu.RLock()
	dv, ok := s.domains[domain]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	// 先查该域保险库：只有该域自己生成过的令牌才可能存在，
	// 因此跨域令牌天然无法还原。
	s.mu.RLock()
	v, ok := dv.tokens[token]
	s.mu.RUnlock()
	return v, ok
}

// DomainToken 用指定域对一个值生成令牌（供测试/需要预先建令牌的场景）。
func (s *Service) DomainToken(domain, value string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("%w: empty token domain", ErrInvalidRule)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dv, err := s.getOrCreateDomain(domain)
	if err != nil {
		return "", err
	}
	tok := computeToken(dv.key, value)
	dv.tokens[tok] = value
	return tok, nil
}
