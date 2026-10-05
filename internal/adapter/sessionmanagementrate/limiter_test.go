package sessionmanagementrate

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedBoundAndSeparateStages(t *testing.T) {
	l, e := New(3, 2, 1, 2)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !l.AllowSource("one", now) || !l.AllowAccount("one", now) {
		t.Fatal("source and account namespaces collide")
	}
	if l.AllowAccount("one", now) || l.AllowAccount("two", now) {
		t.Fatal("quota or shared capacity bypass")
	}
	if !l.AllowSource("one", now) || l.AllowSource("one", now) || l.AllowSource("two", now) {
		t.Fatal("source/global quota bypass")
	}
	if !l.AllowSource("two", now.Add(time.Minute)) || !l.AllowAccount("two", now.Add(time.Minute)) {
		t.Fatal("expired buckets not reused")
	}
}
func TestAccountQuotaConcurrent(t *testing.T) {
	l, _ := New(100, 100, 7, 100)
	now := time.Now()
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.AllowAccount("account", now) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 7 {
		t.Fatal(admitted.Load())
	}
}
