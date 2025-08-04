// Package concurrency provides a simple utility for running tasks on a slice in parallel.
package concurrency

import (
	"fmt"
	"sync"
	"votegral/pkg/context"
)

// minItemsForParallel is the threshold needed to be eligible for running in parallel.
const minItemsForParallel = 101

// ForEach executes a worker function for each item in a slice, distributing the work across designated # of CPU cores.
func ForEach[T any](ctx *context.OperationContext, items []T, workerFunc func(index int, item T) error) error {
	numItems := len(items)
	if numItems == 0 {
		return nil
	}

	parallel := ctx.Config.Cores > 1

	// If parallelism is not configured or the slice is too small, run a simple for loop.
	if !parallel || numItems < minItemsForParallel {
		for i, item := range items {
			if err := workerFunc(i, item); err != nil {
				return err // Fail fast on the first error in sequential mode.
			}
		}
		return nil
	}

	// --- Parallel Execution Path ---
	jobs := make(chan int, numItems)
	errs := make(chan error, numItems)
	var wg sync.WaitGroup

	numWorkers := ctx.Config.Cores
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				item := items[i]
				if err := workerFunc(i, item); err != nil {
					errs <- err
				}
			}
		}()
	}

	for i := 0; i < numItems; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	close(errs)

	if len(errs) > 0 {
		return <-errs // Return the first error found.
	}

	return nil
}

// Map executes a worker function for each item in a slice and returns a new slice
// containing the transformed results. The workerFunc takes an item of type T and
// must return a transformed item of type U.
func Map[T any, U any](ctx *context.OperationContext, items []T, workerFunc func(item T) (U, error)) ([]U, error) {
	numItems := len(items)
	if numItems == 0 {
		return nil, fmt.Errorf("no items to map")
	}

	parallel := ctx.Config.Cores > 1

	// If parallelism is not configured or the slice is too small, run sequentially.
	if !parallel || numItems < minItemsForParallel {
		results := make([]U, numItems)
		for i, item := range items {
			res, err := workerFunc(item)
			if err != nil {
				return nil, err // Fail fast on the first error.
			}
			results[i] = res
		}
		return results, nil
	}

	// --- Parallel Execution Path ---
	results := make([]U, numItems)
	jobs := make(chan int, numItems)
	errs := make(chan error, numItems)
	var wg sync.WaitGroup

	numWorkers := ctx.Config.Cores
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				item := items[i]
				res, err := workerFunc(item)
				if err != nil {
					errs <- err
					continue
				}
				results[i] = res
			}
		}()
	}

	for i := 0; i < numItems; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
	close(errs)

	if len(errs) > 0 {
		return nil, <-errs // Return the first error found.
	}

	return results, nil
}
