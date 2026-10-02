// Package dataset 提供内存数据集与可变的主体授权状态。
// 全部数据保存在本地内存中，不依赖任何外部服务。
package dataset

import (
	"sync"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

// DataSet 内存受保护数据与授权表，并发安全。
type DataSet struct {
	mu      sync.RWMutex
	records map[string]model.Record
	grants  map[string]model.Grant // grantID -> grant
	clock   func() time.Time
}

// New 创建内存数据集。
func New(clock func() time.Time) *DataSet {
	if clock == nil {
		clock = time.Now
	}
	return &DataSet{
		records: make(map[string]model.Record),
		grants:  make(map[string]model.Grant),
		clock:   clock,
	}
}

// PutRecord 写入/更新记录（字段做防御性拷贝）。
func (d *DataSet) PutRecord(r model.Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fields := make(map[string]string, len(r.Fields))
	for k, v := range r.Fields {
		fields[k] = v
	}
	r.Fields = fields
	d.records[r.Resource] = r
}

// GetRecord 按资源标识读取记录，返回深拷贝避免调用方修改共享状态。
func (d *DataSet) GetRecord(resource string) (model.Record, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.records[resource]
	if !ok {
		return model.Record{}, false
	}
	fields := make(map[string]string, len(r.Fields))
	for k, v := range r.Fields {
		fields[k] = v
	}
	r.Fields = fields
	return r, true
}

// Reclassify 原子调整一条记录的数据分级，对之后的请求立即生效。
// 更新在同一把写锁内完成，并发访问要么读到旧分级、要么读到新分级，
// 单次判定不会读到半新半旧的分级状态。记录不存在时返回 false。
func (d *DataSet) Reclassify(resource string, level model.Sensitivity, at time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.records[resource]
	if !ok {
		return false
	}
	r.Sensitivity = level
	d.records[resource] = r
	return true
}

// PutGrant 写入授权（字段做防御性拷贝）。
func (d *DataSet) PutGrant(g model.Grant) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if g.UpdatedAt.IsZero() {
		g.UpdatedAt = d.clock()
	}
	if len(g.Purposes) > 0 {
		purposes := make([]string, len(g.Purposes))
		copy(purposes, g.Purposes)
		g.Purposes = purposes
	}
	if g.MaxSensitivity != nil {
		cap := *g.MaxSensitivity
		g.MaxSensitivity = &cap
	}
	d.grants[g.ID] = g
}

// RevokeGrant 撤销授权，撤销立即生效（后续判定读到 Revoked=true）。
func (d *DataSet) RevokeGrant(id string, at time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	g, ok := d.grants[id]
	if !ok || g.Revoked {
		return false
	}
	g.Revoked = true
	g.UpdatedAt = at
	d.grants[id] = g
	return true
}

// FindGrant 查找主体对资源的当前授权。
// 同一主体对同一资源存在多条时，返回最近更新的一条；返回拷贝。
func (d *DataSet) FindGrant(subjectID, resource string) *model.Grant {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var best *model.Grant
	for _, g := range d.grants {
		if g.SubjectID != subjectID || g.Resource != resource {
			continue
		}
		g := g
		if best == nil || g.UpdatedAt.After(best.UpdatedAt) {
			best = &g
		}
	}
	return best
}
