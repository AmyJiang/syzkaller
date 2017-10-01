package diff

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/syzkaller/prog"
)

func readProg(scanner *bufio.Scanner) (*prog.Prog, error) {
	var buf bytes.Buffer
	for scanner.Scan() && scanner.Text() != "" {
		if _, err := buf.WriteString(scanner.Text() + "\n"); err != nil {
			return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
		}
	}
	prog, err := prog.Deserialize(buf.Bytes())
	if err != nil || prog == nil || len(prog.Calls) == 0 {
		return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
	}
	return prog, nil
}

func readStates(scanner *bufio.Scanner) ([]*ExecResult, error) {
	var rs []*ExecResult
	var r *ExecResult
	for scanner.Scan() && !strings.HasPrefix(scanner.Text(), "## ") {
		if strings.HasPrefix(scanner.Text(), "Failed") {
			return nil, fmt.Errorf("%s", scanner.Text())
		}
		if strings.HasPrefix(scanner.Text(), "###") {
			r = &ExecResult{
				FS:        strings.Split(scanner.Text(), " ")[1],
				Res:       []int32{},
				Errnos:    []int32{},
				State:     []byte{},
				StateHash: [20]byte{},
			}
		}
		for scanner.Scan() && scanner.Text() != "" {
			r.State = append(r.State, []byte(scanner.Text()+"\n")...)
		}
		r.StateHash = sha1.Sum(r.State)
		rs = append(rs, r)
	}

	if rs == nil {
		return nil, fmt.Errorf("No filesystem states")
	}
	return rs, nil
}

func readReturns(scanner *bufio.Scanner, rs []*ExecResult) error {
	var i, rt, errno int
	i = 0
	for scanner.Scan() && scanner.Text() != "" {
		fields := strings.Fields(scanner.Text())
		for _, f := range fields {
			if _, err := fmt.Sscanf(f, "%d(%d)", &rt, &errno); err == nil {
				rs[i].Res = append(rs[i].Res, int32(rt))
				rs[i].Errnos = append(rs[i].Errnos, int32(errno))
			} else {
				// nil(nil), executor stops early
				break
			}
		}
		i++

	}
	if i != len(rs) {
		return fmt.Errorf("Corrupted State field: len=%d", i)
	}
	return nil
}

// ParseMinProg extracts the minimized program from the reproducing log.
func ParseMinProg(log string) (*prog.Prog, error) {
	logFile, err := os.Open(log)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()

	var minProg *prog.Prog
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "## Minimized") {
			minProg, err = readProg(scanner)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	if minProg == nil {
		return nil, fmt.Errorf("empty minimized prog")
	}
	return minProg, nil
}

// ParseReproLog parses the reproducing log of a discrepancy-inducing program.
// prog: test program
// minProg: minimized equivalent program
// rs: execution results
// err: parsing error
func ParseReproLog(log string, skipProg bool, skipMin bool) (prog *prog.Prog, minProg *prog.Prog, rs []*ExecResult, err error) {
	var logFile *os.File
	logFile, err = os.Open(log)
	if err != nil {
		return
	}
	defer logFile.Close()

	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		if !skipProg {
			if strings.HasPrefix(scanner.Text(), "## Prog") {
				prog, err = readProg(scanner)
				if err != nil {
					return
				}
			}
		}
		if strings.HasPrefix(scanner.Text(), "## State") {
			rs, err = readStates(scanner)
			if err != nil {
				return
			}
		}
		if strings.HasPrefix(scanner.Text(), "## Return") {
			err = readReturns(scanner, rs)
			if err != nil {
				return
			}
		}
		if !skipMin {
			if strings.HasPrefix(scanner.Text(), "## Minimized") {
				minProg, err = readProg(scanner)
				if err != nil {
					return
				}
				break // MinProg is the last section
			}
		}
	}
	err = scanner.Err()
	if err != io.EOF && err != nil {
		return
	}
	return
}
