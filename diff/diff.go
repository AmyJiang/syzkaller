package diff

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/google/syzkaller/prog"
)

// ExecResult holds the execution results of differential testing.
type ExecResult struct {
	State     []byte   // filesystem state description
	StateHash [20]byte // SHA1 hash of the filesystem state description
	Res       []int32  // Return values of the syscalls
	Errnos    []int32  // Errnos of the syscalls
	FS        string   // Working directory in the tested filesystem
}

func (r ExecResult) String() string {
	return fmt.Sprintf("{FS:%s\n  State:%s  Res:%v\n  Errnos:%v}\n", r.FS, r.State, r.Res, r.Errnos)
}

// DiffTypes describes types of discrepancies in filesystem states
var DiffTypes = [][]byte{
	[]byte("Name"),
	[]byte("Mode"),
	[]byte("Uid"),
	[]byte("Gid"),
	[]byte("Link"),
	[]byte("Size"),
}

// CheckHash cross-checks the hashes of file system states and returns true
// if at least one file system is in a different state from others.
func CheckHash(rs []*ExecResult) bool {
	for i := 1; i < len(rs); i += 1 {
		if !reflect.DeepEqual(rs[0].StateHash, rs[i].StateHash) {
			return true
		}
	}
	return false
}

// CheckReturns cross-checks the return values of syscalls executed in tested
// filesystems and returns true if at least one syscall returns differently
// in two or more file systems.
func CheckReturns(rs []*ExecResult) bool {
	for i := 1; i < len(rs); i += 1 {
		if !reflect.DeepEqual(rs[0].Res, rs[i].Res) {
			return true
		}
		if !reflect.DeepEqual(rs[0].Errnos, rs[i].Errnos) {
			return true
		}
	}
	return false
}

// diffState returns a description of differences between two filesystem states.
func diffState(s0 []byte, s []byte) (diff []byte) {
	files := bytes.Fields(s)
	files0 := bytes.Fields(s0)
	if len(files) != len(files0) {
		diff = append(diff, "File-Num "...)
		return
	}
	for i, _ := range files {
		fields := bytes.Split(files[i], []byte{','})
		fields0 := bytes.Split(files0[i], []byte{','})
		for j, _ := range fields {
			if !reflect.DeepEqual(fields[j], fields0[j]) {
				diff = append(diff, fmt.Sprintf("%s-%s ", fields[0], DiffTypes[j])...)
			}
		}
	}
	return
}

// Difference returns a summary of discrepancies in filesystem ExecResults.
func Difference(rs []*ExecResult, p *prog.Prog) (diff []string) {
	call := -1
	for i := 0; i < len(p.Calls); i++ {
		for _, r := range rs[1:] {
			if r.Res[i] != rs[0].Res[i] || r.Errnos[i] != rs[0].Errnos[i] {
				call = i
				break
			}
		}
	}

	for i, r := range rs {
		d := ""
		if i != 0 { // use the first testfs as oracle
			d = string(diffState(rs[0].State, rs[i].State))
		}

		if call != -1 {
			d += fmt.Sprintf("\n%s()=%d(%d)", p.Calls[call].Meta.Name, r.Res[call], r.Errnos[call])
		}
		diff = append(diff, d)
	}
	return diff
}

// GroupResults assigns same group numbers to identical ExecResults.
func GroupResults(rs []*ExecResult) (groups []int) {
	group_id := make(map[string]int)
	for i, r := range rs {
		hash := string(r.StateHash[:])
		if i == 0 {
			groups = append(groups, 0)
			group_id[hash] = 0
		} else {
			if id, ok := group_id[hash]; ok {
				groups = append(groups, id)
			} else {
				groups = append(groups, i)
				group_id[hash] = i
			}
		}
	}
	return
}
