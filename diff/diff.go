package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/syzkaller/prog"
	"sort"
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

func diffErrno(p *prog.Prog, err1 []int32, err2 []int32) string {
	for i, e1 := range err1 {
		if len(err2) <= i {
			return fmt.Sprintf("%s(%d-nil)", p.Calls[i].Meta.Name, e1)
		}
		if err2[i] != e1 {
			return fmt.Sprintf("%s(%d-%d)", p.Calls[i].Meta.Name, e1, err2[i])
		}
	}
	if len(err1) < len(err2) {
		return fmt.Sprintf("%s(nil-%d)", p.Calls[len(err1)].Meta.Name, err2[len(err1)])
	}
	return ""
}

// Difference returns a summary of discrepancies in filesystem ExecResults.
func Difference(rs []*ExecResult, p *prog.Prog, diffFields []string, checkReturns bool) map[string]string {
	difference := make(map[string]string)
	l := len(rs)
	for i := 0; i < l; i++ {
		for j := i + 1; j < l; j++ {
			k := rs[i].FS + "-" + rs[j].FS
			d := diffState(rs[i].State, rs[j].State, diffFields)
			if checkReturns {
				d += diffErrno(p, rs[i].Errnos, rs[j].Errnos)
			}
			difference[k] = strings.TrimSpace(d)
		}
	}
	return difference
}

func Hash(delta map[string]string) string {
	var keys []string
	for k := range delta {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("{")
	for i, k := range keys {
		if i != 0 {
			buf.WriteString(",")
		}
		key, _ := json.Marshal(k)
		buf.Write(key)
		buf.WriteString(":")
		val, _ := json.Marshal(delta[k])
		buf.Write(val)
	}
	buf.WriteString("}")
	return string(buf.Bytes())
}

func HasDifference(delta map[string]string) bool {
	for k := range delta {
		if delta[k] != "" {
			return true
		}
	}
	return false
}
