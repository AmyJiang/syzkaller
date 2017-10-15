package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/syzkaller/prog"
	"strings"
)

// ExecResult holds the execution result of one test fs
type ExecResult struct {
	State     []byte   // filesystem state description
	StateHash [20]byte // SHA1 hash of state description
	Res       []int32  // Return values of the syscalls
	Errnos    []int32  // Errnos of the syscalls
	FS        string   // testfs
}

func (r ExecResult) String() string {
	return fmt.Sprintf("{FS:%s\n  State:%s  Res:%v\n  Errnos:%v}\n", r.FS, r.State, r.Res, r.Errnos)
}

// DiffTypes describes the components of the state
var DiffTypes = []string{"Name", "Mode", "Uid", "Gid", "Link", "Size"}

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
		// if !reflect.DeepEqual(rs[0].Res, rs[i].Res) {
		//	return true
		// }
		if !reflect.DeepEqual(rs[0].Errnos, rs[i].Errnos) {
			return true
		}
	}
	return false
}

func parseState(s []byte) [](map[string]string) {
	var state [](map[string]string)
	lines := bytes.Fields(s)
	for _, s := range lines {
		s = bytes.Trim(s, "\x00")
		fields := bytes.Split(s, []byte{','})
		stat := make(map[string]string)
		for i, f := range fields {
			stat[DiffTypes[i]] = string(f)
		}
		state = append(state, stat)
	}
	return state
}

// diffState returns a description of differences between two filesystem states.
// diffFields msut be a subset of DiffTypes
func diffState(s0 []byte, s1 []byte, diffFields []string) string {
	s0_parsed := parseState(s0)
	s1_parsed := parseState(s1)

	diff := ""
	if len(s0_parsed) != len(s1_parsed) {
		diff = diff + "File-Num "
		return diff
	}
	for i, _ := range s0_parsed {
		for _, k := range diffFields {
			if s0_parsed[i][k] != s1_parsed[i][k] {
				diff = diff + fmt.Sprintf("%s-%s ", s0_parsed[i]["Name"], k)
			}
		}
	}
	return diff
}

func firstDiffRet(p *prog.Prog, rs []*ExecResult) int {
	for i := 0; i < len(rs[0].Res); i++ {
		for _, r := range rs[1:] {
			if len(r.Res) <= i || len(r.Errnos) <= i {
				return i
			}
			if r.Errnos[i] != rs[0].Errnos[i] {
				// if r.Res[i] != rs[0].Res[i] || r.Errnos[i] != rs[0].Errnos[i] {
				return i
			}
		}
	}
	return -1
}

func Hash(delta map[string]string) string {
	data, _ := json.Marshal(delta)
	return string(data)
}

// Difference returns a summary of discrepancies in filesystem ExecResults.
func Difference(rs []*ExecResult, p *prog.Prog, diffFields []string, checkReturns bool) map[string]string {
	delta := make(map[string]string)
	call := -1
	if checkReturns == true {
		call = firstDiffRet(p, rs)
	}

	ref := 0
	for i, r := range rs {
		if r.FS == "/testfs1" {
			// TODO: possible not to hard-code?
			ref = i
			break
		}
	}

	for i, r := range rs {
		d := ""
		if i != ref { // use rs[ref] as oracle
			d = diffState(rs[ref].State, rs[i].State, diffFields)
		}

		if call != -1 {
			if len(r.Res) > call && len(r.Errnos) > call {
				d += fmt.Sprintf("%s(errno %d)", p.Calls[call].Meta.Name, r.Errnos[call])
				// d += fmt.Sprintf("\n%s()=%d(%d)", p.Calls[call].Meta.Name, r.Res[call], r.Errnos[call])
			} else {
				d += fmt.Sprintf("%s()=nil(nil)", p.Calls[call].Meta.Name)
			}
		}
		delta[r.FS] = strings.TrimSpace(d)
	}
	return delta
}

func HasDifference(delta map[string]string) bool {
	for k := range delta {
		if delta[k] != "" {
			return true
		}
	}
	return false
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
