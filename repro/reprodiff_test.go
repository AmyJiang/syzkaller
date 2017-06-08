package repro

import (
	"testing"
)

func init() {
}

func TestParseStates(t *testing.T) {
	log := "./test.log"
	states, groups, deltas, err := ParseStates(log)
	if err != nil {
		t.Fatalf("failed to ParseStates: %v", err)
	}
	t.Logf("States:\n %v", states)
	t.Logf("Groups:\n %v", groups)
	t.Logf("Deltas:\n %v", deltas)
}
