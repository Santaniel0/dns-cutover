// Package workpool runs a slice of jobs on a fixed number of goroutines.
package workpool

import (
	"context"
	"sync"
)

// Run calls fn for every job on at most workers goroutines and passes each
// result to sink. sink runs on the calling goroutine, so it may touch the
// caller's state without locks.
//
// When ctx is canceled no new jobs are handed out; jobs already running get
// the canceled ctx and are expected to return quickly. Run returns only after
// every goroutine it started has exited, and then reports ctx.Err().
func Run[J, R any](ctx context.Context, workers int, jobs []J, fn func(context.Context, J) R, sink func(R)) error {
	workers = max(1, min(workers, len(jobs)))
	feed := make(chan J)
	out := make(chan R)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range feed {
				out <- fn(ctx, j)
			}
		})
	}
	go func() {
		defer close(feed)
		for _, j := range jobs {
			// Checked before the select, because a select with both cases
			// ready picks at random and would keep feeding after cancel.
			if ctx.Err() != nil {
				return
			}
			select {
			case feed <- j:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	for r := range out {
		sink(r)
	}
	return ctx.Err()
}
