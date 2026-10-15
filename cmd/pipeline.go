package cmd

import (
	"context"
	"runtime"
	"sync"

	"github.com/lenny-ts/caddy-analyzer/pkg/parser"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

type parsedResult struct {
	seq    uint64
	source string
	entry  types.Entry
	err    error
}

// tagEntry stamps the parsed entry with the canonical source of its input
// line. Parsing stays source-agnostic; the label is attached here after the
// workers return, which guarantees concurrent workers can never swap labels.
func tagEntry(entry types.Entry, source string) {
	switch e := entry.(type) {
	case *types.LogEntry:
		e.Source = source
	case *types.OperationalEntry:
		e.Source = source
	}
}

// processParsedLines parses input concurrently and reduces results in input
// order. Keeping the reducer ordered preserves stateful detector semantics.
// Every result (HTTP entry, operational entry, or parse failure) carries the
// source label of its input line.
func processParsedLines(ctx context.Context, lines <-chan types.SourcedLine, workers int, fn func(source string, entry types.Entry, err error)) {
	if workers <= 1 {
		for line := range lines {
			entry, err := parser.Parse(line.Text)
			if err == nil {
				tagEntry(entry, line.Source)
			}
			fn(line.Source, entry, err)
		}
		return
	}

	type job struct {
		seq    uint64
		source string
		line   string
	}
	jobs := make(chan job)
	results := make(chan parsedResult, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				entry, err := parser.Parse(j.line)
				results <- parsedResult{seq: j.seq, source: j.source, entry: entry, err: err}
			}
		}()
	}

	go func() {
		seq := uint64(0)
		for line := range lines {
			select {
			case jobs <- job{seq: seq, source: line.Source, line: line.Text}:
				seq++
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	pending := make(map[uint64]parsedResult)
	next := uint64(0)
	for result := range results {
		// The label is attached on the reducing goroutine only, after
		// ordering is restored, so it can never be attributed to another
		// source's line.
		if result.err == nil {
			tagEntry(result.entry, result.source)
		}
		pending[result.seq] = result
		for {
			ready, ok := pending[next]
			if !ok {
				break
			}
			fn(ready.source, ready.entry, ready.err)
			delete(pending, next)
			next++
		}
	}
}

func configuredWorkers() int {
	if flagWorkers == 0 {
		return runtime.GOMAXPROCS(0)
	}
	return flagWorkers
}
