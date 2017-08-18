package diff

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
)

// ExecResult holds the execution results of differential testing.
type ExecResult struct {
	State     []byte        // filesystem state description
	StateHash [20]byte      // SHA1 hash of the filesystem state description
	Res       []int32       // Return values of the syscalls
	Errnos    []int32       // Errnos of the syscalls
	FS        string        // Working directory in the tested filesystem
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
func Difference(rs []*ExecResult) []byte {
	var diff []byte
	for i, r := range rs {
		fs := strings.Split(r.FS, "/")[1]
		if i == 0 {
			continue
		}
		d := diffState(rs[0].State, rs[i].State)
		if len(d) > 0 {
			diff = append(diff, fmt.Sprintf("%s:%s\n", fs, d)...)
		}
	}
	return diff
}
