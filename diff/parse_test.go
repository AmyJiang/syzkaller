package diff

import (
	"testing"
)

func init() {
}

func TestParseReproLog(t *testing.T) {
	logs := []string{"./test.log"}
	for _, log := range logs {
		prog, minProg, rs, err := ParseReproLog(log, false, false)
		if err != nil {
			t.Fatalf("failed to ParseStates: %v", err)
		}
		t.Logf("Prog: %s", prog)
		t.Logf("MinProg: %s", minProg)
		t.Logf("Execution Results:\n %+v", rs)
	}
}
