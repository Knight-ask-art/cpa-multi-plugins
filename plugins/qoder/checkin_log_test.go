package main

import "testing"

func TestCheckinLogLine_OK(t *testing.T) {
	out := map[string]any{
		"success":        true,
		"message":        "签到成功 +100",
		"reward_credits": float64(100),
		"credits_before": int64(994),
		"credits_after":  int64(1094),
		"credits_delta":  int64(100),
	}
	got := checkinLogLine("qoder-cn-x.json", out)
	want := "qoder: checkin OK qoder-cn-x.json reward=100 credits 994→1094 (+100) msg=签到成功 +100"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestCheckinLogLine_AlreadyAndSkip(t *testing.T) {
	// Manual-path shape (checkinOneAccount): skipped/already, streak present.
	out := map[string]any{"success": true, "skipped": true, "reason": "already", "message": "今日已签到", "streak_days": int64(7)}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin SKIP[already] a.json streak=7 msg=今日已签到" {
		t.Fatalf("already: %q", got)
	}
	// Scheduled-path shape (autoCheckinVerdict): same line, no streak.
	if got := checkinLogLine("a.json", autoCheckinVerdict(map[string]any{"result": "ALREADY_CLAIMED"})); got != "qoder: checkin SKIP[already] a.json msg=今日已签到" {
		t.Fatalf("already(auto): %q", got)
	}
	out = map[string]any{"success": true, "skipped": true, "reason": "blocked", "message": "同人已领取"}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin SKIP[blocked] a.json msg=同人已领取" {
		t.Fatalf("skip: %q", got)
	}
}

func TestCheckinLogLine_FailAndError(t *testing.T) {
	out := map[string]any{"success": false, "message": "result=FAILED"}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin FAIL a.json msg=result=FAILED" {
		t.Fatalf("fail: %q", got)
	}
	out = map[string]any{"error": "status: http 401"}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin ERROR a.json err=status: http 401" {
		t.Fatalf("error: %q", got)
	}
}

func TestCheckinLogLine_FailureCodeAndNoDelta(t *testing.T) {
	// Claimed but the pool did not move (coupon / lagging grant): log the
	// verdict explicitly so a "签到成功但积分没变" report is one grep away.
	out := map[string]any{"reason": "not_eligible", "failure_code": "OUT_OF_STOCK", "message": "暂不可领取：OUT_OF_STOCK"}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin FAIL a.json code=OUT_OF_STOCK msg=暂不可领取：OUT_OF_STOCK" {
		t.Fatalf("code: %q", got)
	}
	out = map[string]any{"success": true, "message": "签到成功", "reward_credits": float64(100), "credits_before": int64(100), "credits_after": int64(100), "credits_delta": int64(0)}
	if got := checkinLogLine("a.json", out); got != "qoder: checkin OK a.json reward=100 credits 100→100 (+0) msg=签到成功" {
		t.Fatalf("no-delta: %q", got)
	}
}
