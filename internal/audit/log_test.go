package audit

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/data-access-gateway-go/internal/model"
)

func TestAppendGetClone(t *testing.T) {
	l := NewLog()
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	id, err := l.Append(Entry{
		Time: now, SubjectID: "u1", Resource: "r1", Purpose: "research",
		Decision: model.DecisionMask, PolicyVersion: "v1",
		Basis:        model.DecisionBasis{Factors: []string{"f1"}},
		MaskedFields: []string{"ssn"},
	})
	if err != nil || id != 1 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	e, ok := l.Get(1)
	if !ok || e.SubjectID != "u1" {
		t.Fatal("get failed")
	}
	// 修改返回的拷贝不影响存储。
	e.Basis.Factors[0] = "tampered"
	e.MaskedFields[0] = "tampered"
	e2, _ := l.Get(1)
	if e2.Basis.Factors[0] != "f1" || e2.MaskedFields[0] != "ssn" {
		t.Fatal("audit storage leaked mutable state")
	}
	if strings.Contains(strings.ToUpper(strings.Join(e2.Basis.Factors, ",")), "ALICE") {
		t.Fatal("audit should not hold raw values")
	}
}

func TestConcurrentAppend(t *testing.T) {
	l := NewLog()
	var wg sync.WaitGroup
	const n = 100
	ids := make([]int64, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			<-start
			id, _ := l.Append(Entry{SubjectID: "u", Resource: "r", Decision: model.DecisionAllow})
			ids[i] = id
		}()
	}
	close(start)
	wg.Wait()
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate audit id %d", id)
		}
		seen[id] = true
	}
	if len(l.List()) != n {
		t.Fatalf("list len = %d", len(l.List()))
	}
}
