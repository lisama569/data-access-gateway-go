// Package policy 管理策略版本的发布、归档与按版本读取。
//
// 版本生命周期：EffectiveAt 起对新访问生效；RetiresAt 起停止服务新访问
// （Active 不再返回该版本），但版本本身永久保留在归档中，供历史结论复现。
package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// Store 保存全部策略版本（含已归档版本），并发安全。
type Store struct {
	mu       sync.RWMutex
	versions map[string]model.Policy
	order    []string // 发布顺序
}

// NewStore 创建空策略存储。
func NewStore() *Store {
	return &Store{versions: make(map[string]model.Policy)}
}

// Publish 发布一个新版本。版本号不可重复，生效时间必须早于退役时间。
func (s *Store) Publish(p model.Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy version is empty")
	}
	if !p.RetiresAt.IsZero() && !p.EffectiveAt.Before(p.RetiresAt) {
		return fmt.Errorf("policy %s: effective_at must be before retires_at", p.Version)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[p.Version]; ok {
		return fmt.Errorf("policy version %s already exists", p.Version)
	}
	s.versions[p.Version] = p
	s.order = append(s.order, p.Version)
	return nil
}

// Active 返回 at 时刻有效的最新发布版本（已生效且未退役）。
// 若显式退役时间为零值，表示长期有效。
func (s *Store) Active(at time.Time) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best model.Policy
	found := false
	// 按发布顺序，后发布的版本优先（要求新版本 EffectiveAt 不早于旧版本时也成立）。
	for _, v := range s.order {
		p := s.versions[v]
		if at.Before(p.EffectiveAt) {
			continue
		}
		if !p.RetiresAt.IsZero() && !at.Before(p.RetiresAt) {
			continue
		}
		best = p
		found = true
	}
	if !found {
		return model.Policy{}, fmt.Errorf("no active policy at %s", at.Format(time.RFC3339))
	}
	return best, nil
}

// Version 读取任意版本（含归档版本，供历史复现）。
func (s *Store) Version(version string) (model.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.versions[version]
	return p, ok
}

// Versions 返回全部版本号（按发布顺序）。
func (s *Store) Versions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}
