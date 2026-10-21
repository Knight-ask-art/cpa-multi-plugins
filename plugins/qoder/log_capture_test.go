package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestCheckinLogLineReachesStdLogger(t *testing.T) {
	var buf bytes.Buffer
	oldOut, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() { log.SetOutput(oldOut); log.SetFlags(oldFlags); log.SetPrefix(oldPrefix) }()
	log.Printf("%s", strings.Replace(checkinLogLine("x.json", map[string]any{"success": true, "skipped": true, "reason": "already"}), "qoder: checkin ", "qoder: checkin(manual) ", 1))
	if !strings.Contains(buf.String(), "qoder: checkin(manual) SKIP[already] x.json") {
		t.Fatalf("log output = %q", buf.String())
	}
}
