package diff

import (
	"testing"
)

func TestDifference(t *testing.T) {
	log := "./test.log"
	prog, _, rs, err := ParseReproLog(log, false, true)
	if err != nil {
		t.Fatalf("failed to ParseStates: %v", err)
	}
	t.Logf("Deltas:\n%s", Difference(rs, prog, DiffTypes, true))
	t.Logf("Deltas(w/o returns):\n%s", Difference(rs, prog, DiffTypes, false))
}

func TestHash(t *testing.T) {
	log := "./test.log"
	prog, _, rs, err := ParseReproLog(log, false, true)
	if err != nil {
		t.Fatalf("failed to ParseStates: %v", err)
	}
	t.Logf("Hash:\n%s", Hash(Difference(rs, prog, DiffTypes, true)))
	t.Logf("Hash(w/o returns):\n%s", Hash(Difference(rs, prog, DiffTypes, false)))
}

func TestTwoLog(t *testing.T) {
	prog, _, rs, _ := ParseReproLog("./linux.log", false, true)
	_, _, rs2, _ := ParseReproLog("./freebsd.log", true, true)
	rs = append(rs, rs2...)
	t.Logf("rs[0]:\n%s", rs[0])
	t.Logf("rs2[0]:\n%s", rs2[0])
	t.Logf("Difference(w/o returns):\n%s", Hash(Difference(rs, prog, DiffTypes, false)))
}
