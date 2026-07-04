// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workercache_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/workercache"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/testing/protocmp"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestCache_NotReadyBeforeStart(t *testing.T) {
	c := workercache.New(newFakeStore(), time.Hour)
	_, err := c.Workers()
	if err == nil {
		t.Fatal("expected error from Workers before Start, got nil")
	}
}

func TestCache_SyncsOnStart(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	w2 := makeWorker("ns", "pod2", 1)

	c := workercache.New(newFakeStore(w1, w2), time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got, err := c.Workers()
	if err != nil {
		t.Fatalf("Workers: %v", err)
	}
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_CreatedEvent(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	w := makeWorker("ns", "pod1", 1)
	fs.send(store.WorkerEvent{Type: store.WorkerEventCreated, Worker: w})

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_UpdatedEvent_NewerVersionApplied(t *testing.T) {
	w := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	updated := makeWorker("ns", "pod1", 2)
	updated.Assignment = &ateapipb.Assignment{Actor: &ateapipb.ActorRef{Name: "actor-1"}}
	fs.send(store.WorkerEvent{Type: store.WorkerEventUpdated, Worker: updated})

	eventually(t, func() bool {
		workers, err := c.Workers()
		if err != nil || len(workers) != 1 || workers[0].Assignment == nil {
			return false
		}
		wass := workers[0].Assignment
		return wass.Actor.Name == "actor-1"
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{updated}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_UpdatedEvent_OlderVersionIgnored(t *testing.T) {
	w := makeWorker("ns", "pod1", 5)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Send a stale update followed by a sentinel we can detect.
	stale := makeWorker("ns", "pod1", 3)
	stale.Assignment = &ateapipb.Assignment{Actor: &ateapipb.ActorRef{Name: "stale-actor"}}
	fs.send(store.WorkerEvent{Type: store.WorkerEventUpdated, Worker: stale})

	sentinel := makeWorker("ns", "pod2", 1)
	fs.send(store.WorkerEvent{Type: store.WorkerEventCreated, Worker: sentinel})

	// Wait for the sentinel to be processed so we know the stale event was also handled.
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w, sentinel}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_DeletedEvent(t *testing.T) {
	w := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	fs.send(store.WorkerEvent{
		Type:   store.WorkerEventDeleted,
		Worker: &ateapipb.Worker{WorkerNamespace: "ns", WorkerPod: "pod1"},
	})

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 0
	}, 2*time.Second)
}

func TestCache_Disconnect_ResyncsWithFreshSnapshot(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Add a worker to the store snapshot and disconnect to trigger resync.
	w2 := makeWorker("ns", "pod2", 1)
	fs.setWorkers(w1, w2)
	fs.disconnect()

	// After resync the cache should reflect the updated snapshot.
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after resync (-want +got):\n%s", diff)
	}
}

func TestCache_MultipleDisconnects(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Disconnect three times, each time adding a worker to the snapshot.
	for i := range 3 {
		pod := makeWorker("ns", string(rune('a'+i)), 1)
		fs.setWorkers(append(fs.workers[:i], pod)...)
		fs.disconnect()

		want := i + 1
		eventually(t, func() bool {
			workers, err := c.Workers()
			return err == nil && len(workers) == want
		}, 2*time.Second)
	}
}

func TestCache_WatchClosedOnListWorkersFailure(t *testing.T) {
	fs := newFakeStore()
	fs.listErr = errors.New("valkey unavailable")
	c := workercache.New(fs, time.Hour)

	if err := c.Start(t.Context()); err == nil {
		t.Fatal("expected Start to fail when ListWorkers errors")
	}

	fs.mu.Lock()
	closes := fs.closes
	fs.mu.Unlock()
	if closes != 1 {
		t.Fatalf("expected watch to be closed once on sync failure, got %d closes", closes)
	}
}

func TestCache_WatchClosedOnShutdown(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cancel()

	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 1
	}, 2*time.Second)
}

func TestCache_WatchClosedOnDisconnectAndShutdown(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Disconnect: the old watch should be closed and a new one opened.
	fs.disconnect()
	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 1
	}, 2*time.Second)

	// Shutdown: the new watch should also be closed.
	cancel()
	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 2
	}, 2*time.Second)
}

func TestCache_Relist_RecoversFromMissedCreate(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Add a worker directly to the store without sending a watch event,
	// simulating a silent PUBLISH failure.
	w2 := makeWorker("ns", "pod2", 1)
	fs.setWorkers(w1, w2)

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after relist (-want +got):\n%s", diff)
	}
}

func TestCache_Relist_RecoversFromMissedDelete(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	w2 := makeWorker("ns", "pod2", 1)
	fs := newFakeStore(w1, w2)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Remove a worker from the store without a watch event,
	// simulating a silent PUBLISH failure on delete.
	fs.setWorkers(w1)

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after relist (-want +got):\n%s", diff)
	}
}

func TestCache_Relist_FailureIsNonFatal(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Make ListWorkers fail to simulate a transient Valkey error.
	fs.mu.Lock()
	fs.listErr = errors.New("valkey unavailable")
	fs.mu.Unlock()

	// Wait long enough for at least one relist attempt.
	time.Sleep(50 * time.Millisecond)

	// Clear the error; the cache should still be usable with the old snapshot.
	fs.mu.Lock()
	fs.listErr = nil
	fs.mu.Unlock()

	workers, err := c.Workers()
	if err != nil {
		t.Fatalf("Workers: %v", err)
	}
	if diff := cmp.Diff([]*ateapipb.Worker{w1}, workers, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_Metrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	w1 := makeWorker("ns", "pod1", 1)
	w2 := makeWorker("ns", "pod2", 1)
	fs := newFakeStore(w1, w2)
	c := workercache.New(fs, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if got := gaugeValue(t, reader, "ateapi.workercache.workers"); got != 2 {
		t.Errorf("workers gauge after start = %d, want 2", got)
	}
	if got := counterValue(t, reader, "ateapi.workercache.resyncs"); got != 0 {
		t.Errorf("resyncs counter after start = %d, want 0", got)
	}

	// Disconnect with a smaller snapshot: the resync counter should tick and
	// the gauge should track the new size.
	fs.setWorkers(w1)
	fs.disconnect()
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)

	if got := counterValue(t, reader, "ateapi.workercache.resyncs"); got != 1 {
		t.Errorf("resyncs counter after disconnect = %d, want 1", got)
	}
	if got := gaugeValue(t, reader, "ateapi.workercache.workers"); got != 1 {
		t.Errorf("workers gauge after resync = %d, want 1", got)
	}

	// Shutdown unregisters the gauge callback, so the gauge stops reporting.
	cancel()
	eventually(t, func() bool {
		_, ok := metricByName(t, reader, "ateapi.workercache.workers")
		return !ok
	}, 2*time.Second)
}

// metricByName collects from reader and returns the named metric, if reported.
func metricByName(t *testing.T, reader *sdkmetric.ManualReader, name string) (metricdata.Metrics, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m, true
			}
		}
	}
	return metricdata.Metrics{}, false
}

func gaugeValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	m, ok := metricByName(t, reader, name)
	if !ok {
		t.Fatalf("gauge %q not reported", name)
	}
	gauge, ok := m.Data.(metricdata.Gauge[int64])
	if !ok || len(gauge.DataPoints) != 1 {
		t.Fatalf("gauge %q has unexpected data: %#v", name, m.Data)
	}
	return gauge.DataPoints[0].Value
}

// counterValue returns the named counter's value; a counter with no
// recordings yet is not reported at all, which counts as 0.
func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	m, ok := metricByName(t, reader, name)
	if !ok {
		return 0
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 {
		t.Fatalf("counter %q has unexpected data: %#v", name, m.Data)
	}
	return sum.DataPoints[0].Value
}

type fakeStore struct {
	store.Interface

	mu      sync.Mutex
	workers []*ateapipb.Worker
	watchCh chan store.WorkerEvent
	listErr error // if set, ListWorkers returns it
	closes  int   // number of times a returned watch was Closed
}

func newFakeStore(workers ...*ateapipb.Worker) *fakeStore {
	return &fakeStore{
		workers: workers,
		watchCh: make(chan store.WorkerEvent, 16),
	}
}

func (f *fakeStore) WatchWorkers(_ context.Context) (*store.WorkerWatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.NewWorkerWatch(f.watchCh, func() {
		f.mu.Lock()
		f.closes++
		f.mu.Unlock()
	}), nil
}

func (f *fakeStore) ListWorkers(_ context.Context) ([]*ateapipb.Worker, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*ateapipb.Worker, len(f.workers))
	copy(out, f.workers)
	return out, nil
}

func (f *fakeStore) send(event store.WorkerEvent) {
	f.mu.Lock()
	ch := f.watchCh
	f.mu.Unlock()
	ch <- event
}

func (f *fakeStore) setWorkers(workers ...*ateapipb.Worker) {
	f.mu.Lock()
	f.workers = workers
	f.mu.Unlock()
}

func (f *fakeStore) disconnect() {
	f.mu.Lock()
	old := f.watchCh
	f.watchCh = make(chan store.WorkerEvent, 16)
	f.mu.Unlock()
	close(old)
}

func makeWorker(namespace, pod string, version int64) *ateapipb.Worker {
	return &ateapipb.Worker{
		WorkerNamespace: namespace,
		WorkerPod:       pod,
		Version:         version,
	}
}

// workerSortOpt compares workers ignoring ordering.
var workerSortOpt = cmpopts.SortSlices(func(a, b *ateapipb.Worker) bool {
	if a.GetWorkerNamespace() != b.GetWorkerNamespace() {
		return a.GetWorkerNamespace() < b.GetWorkerNamespace()
	}
	return a.GetWorkerPod() < b.GetWorkerPod()
})

// eventually polls condition every 10ms until it returns true or timeout elapses.
func eventually(t *testing.T, condition func() bool, timeout time.Duration) {
	t.Helper()
	err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, timeout, true, func(context.Context) (bool, error) {
		return condition(), nil
	})
	if err != nil {
		t.Fatal("condition not met within timeout")
	}
}
