package main

import (
	"testing"
	"time"
)

// TestNextCheckinTimeIncludesCompensationTicks pins the v0.8.65 minute-offset
// schedule: after the 10:00 tick the next wake is 10:03, then 10:30.
func TestNextCheckinTimeIncludesCompensationTicks(t *testing.T) {
	loc := time.Local
	cases := []struct {
		from time.Time
		want string
	}{
		{time.Date(2026, 10, 21, 10, 0, 5, 0, loc), "10:03"},
		{time.Date(2026, 10, 21, 9, 59, 0, 0, loc), "10:00"},
		{time.Date(2026, 10, 21, 10, 1, 0, 0, loc), "10:03"},
		{time.Date(2026, 10, 21, 10, 4, 0, 0, loc), "10:30"},
		{time.Date(2026, 10, 21, 10, 31, 0, 0, loc), "15:00"},
		{time.Date(2026, 10, 21, 15, 1, 0, 0, loc), "21:00"},
		{time.Date(2026, 10, 21, 21, 1, 0, 0, loc), "22:00"}, // keepalive
		{time.Date(2026, 10, 21, 22, 1, 0, 0, loc), "23:00"},
		{time.Date(2026, 10, 21, 23, 1, 0, 0, loc), "23:30"},
		{time.Date(2026, 10, 21, 23, 31, 0, 0, loc), "10:00"}, // next day
	}
	for _, c := range cases {
		got := nextCheckinTime(c.from).Format("15:04")
		if got != c.want {
			t.Errorf("from %s → %s, want %s", c.from.Format("15:04"), got, c.want)
		}
	}
}
