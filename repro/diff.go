package repro

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/ipc"
	"reflect"
	"strings"
)

var DiffTypes = [][]byte{
	[]byte("Name"),
	[]byte("Mode"),
	[]byte("Uid"),
	[]byte("Gid"),
	[]byte("Link"),
	[]byte("Size"),
}

// diffState returns a description of differences between the states
// of two file systems.
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

// Difference returns a description of discrepancies in filesystem
// states from ExecResult
func Difference(rs []*ipc.ExecResult) []byte {
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
