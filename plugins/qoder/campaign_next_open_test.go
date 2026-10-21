package main

import (
	"testing"
	"time"
)

func TestRowsNextOpenAt(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 5, 0, 0, time.Local)
	st := &campaignStatusResponse{Campaigns: []campaign{
		{CampaignKey: "past", StartAt: now.Add(-time.Hour).Unix()},
		{CampaignKey: "later-2", StartAt: now.Add(2 * time.Hour).Unix()},
		{CampaignKey: "later-1", StartAt: now.Add(time.Hour).Unix()},
		{CampaignKey: "ms-row", StartAt: now.Add(3 * time.Hour).UnixMilli()},
		{CampaignKey: "too-far", StartAt: now.Add(48 * time.Hour).Unix()},
	}}
	got := rowsNextOpenAt(st, now)
	want := now.Add(time.Hour).Unix()
	if got != want {
		t.Fatalf("rowsNextOpenAt = %d, want %d (earliest future start today)", got, want)
	}
	if rowsNextOpenAt(nil, now) != 0 {
		t.Fatal("nil status must report 0")
	}
	if rowsNextOpenAt(&campaignStatusResponse{}, now) != 0 {
		t.Fatal("no rows must report 0")
	}
}

func TestRowsNextOpenAtIgnoresAlreadyOpen(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 5, 0, 0, time.Local)
	st := &campaignStatusResponse{Campaigns: []campaign{{CampaignKey: "open", StartAt: now.Add(-time.Minute).Unix()}}}
	if got := rowsNextOpenAt(st, now); got != 0 {
		t.Fatalf("already-open row reported %d, want 0", got)
	}
}
