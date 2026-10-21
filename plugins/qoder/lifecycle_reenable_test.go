package main

import "testing"

// v0.8.68: the re-enable predicate is region-agnostic — an Intl account whose
// check-in restored its pool is re-enabled exactly like a CN one.
func TestShouldReenableAnyRegion(t *testing.T) {
	funded := &creditsSummary{TotalRemain: 100, TotalSize: 100}
	drained := &creditsSummary{TotalRemain: 0, TotalSize: 100, TotalUsed: 100}
	if !shouldReenable(true, funded) {
		t.Fatal("funded disabled account must be re-enabled")
	}
	if shouldReenable(true, drained) {
		t.Fatal("drained account must stay disabled")
	}
	if shouldReenable(false, funded) {
		t.Fatal("enabled account needs no re-enable")
	}
	if shouldReenable(true, nil) {
		t.Fatal("unknown credits must not re-enable")
	}
}
