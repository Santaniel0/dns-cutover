package workpool

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
)

func TestRunDeliversEveryResult(t *testing.T) {
	jobs := make([]int, 100)
	for i := range jobs {
		jobs[i] = i
	}
	var got []int
	err := Run(context.Background(), 8, jobs, func(_ context.Context, j int) int { return j * 2 }, func(r int) { got = append(got, r) })
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	for i, v := range got {
		if v != i*2 {
			t.Fatalf("result %d = %d", i, v)
		}
	}
	if len(got) != len(jobs) {
		t.Fatalf("got %d results, want %d", len(got), len(jobs))
	}
}

func TestRunBoundsConcurrency(t *testing.T) {
	const workers = 4
	var inFlight, peak atomic.Int32
	// Every job waits until `workers` jobs are running at once, which proves
	// the pool reaches its bound; the peak check proves it never exceeds it.
	release := make(chan struct{})
	var started atomic.Int32
	fn := func(_ context.Context, _ int) int {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		if started.Add(1) == workers {
			close(release)
		}
		<-release
		inFlight.Add(-1)
		return 0
	}
	if err := Run(context.Background(), workers, make([]int, 40), fn, func(int) {}); err != nil {
		t.Fatal(err)
	}
	if p := peak.Load(); p != workers {
		t.Errorf("peak concurrency = %d, want %d", p, workers)
	}
}

func TestRunStopsHandingOutJobsAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	fn := func(ctx context.Context, j int) int {
		if calls.Add(1) == 3 {
			cancel()
		}
		return j
	}
	err := Run(ctx, 2, make([]int, 1000), fn, func(int) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// Two workers may each have picked up one more job while the third
	// was canceling; nothing beyond that.
	if n := calls.Load(); n > 5 {
		t.Errorf("%d jobs ran after cancel at job 3", n)
	}
}

func TestRunNoJobs(t *testing.T) {
	called := false
	if err := Run(context.Background(), 4, nil, func(context.Context, int) int { called = true; return 0 }, func(int) {}); err != nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}
