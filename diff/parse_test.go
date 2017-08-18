package diff

import (
	"testing"
)

func init() {
}

func TestParseReproLog(t *testing.T) {
	logs := []string{"./test.log"}
	for _, log := range logs {
		name, groups, diff, diffRet, err := ParseReproLog(log)
		if err != nil {
			t.Fatalf("failed to ParseStates: %v", err)
		}
		t.Logf("Name:\n %v", name)
		t.Logf("Groups:\n %v", groups)
		t.Logf("Diff:\n %v", diff)
		t.Logf("DiffRet:\n %v", diffRet)
	}
}
