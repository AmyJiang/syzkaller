package repro

import (
	"testing"
)

func init() {
}

func TestParseStates(t *testing.T) {
	logs := []string{"./test.log", "./test_ret.log"}
	for _, log := range logs {
		states, res, groups, deltas, extra, err := ParseStates(log)
		if err != nil {
			t.Fatalf("failed to ParseStates: %v", err)
		}
		t.Logf("States:\n %v", states)
		t.Logf("Returns:\n %v", res)
		t.Logf("Groups:\n %v", groups)
		t.Logf("Deltas:\n %v", deltas)
		t.Logf("Extra:\n %v", extra)
	}
}
