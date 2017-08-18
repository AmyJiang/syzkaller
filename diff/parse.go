package diff

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"os"
	"reflect"
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

// groupStates assigns same group numbers to identical ExecResults.
func groupStates(rs []*ExecResult) (groups []int) {
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

func readReturns(scanner *bufio.Scanner) ([]string, error) {
	var returns []string
	for scanner.Scan() && scanner.Text() != "" {
		returns = append(returns, scanner.Text())
	}
	if returns == nil {
		return nil, fmt.Errorf("No return values")
	}
	return returns, nil
}

func differenceReturns(returns []string) string {
	for _, l := range returns {
		ret := strings.Fields(l)[1:] // strings.Fields(l)[1] is the syscall
		if !reflect.DeepEqual(ret[:len(ret)-1], ret[1:]) {
			return l
		}
	}
	return ""
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
// name: name of the prog (e.g mmap-create-write)
// groups: tested filesystems groups by their ExecResults
// diff: a summary of discrepancies in the filesystems' ExecResults after running the program
// diffRet: the first syscall that returns differently in the filesystems and its return values
// err: error in parsing
func ParseReproLog(log string) (name string, groups []int, diff string, diffRet string, err error) {
	var logFile *os.File
	logFile, err = os.Open(log)
	if err != nil {
		return
	}
	defer logFile.Close()

	var rs []*ExecResult
	var minProg *prog.Prog
	var returns []string

	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "## State") {
			rs, err = readStates(scanner)
			if err != nil {
				return
			}
		}
		if strings.HasPrefix(scanner.Text(), "## Return") {
			returns, err = readReturns(scanner)
			if err != nil {
				return
			}
		}
		if strings.HasPrefix(scanner.Text(), "## Minimized") {
			minProg, err = readProg(scanner)
			if err != nil {
				return
			}
			name = minProg.String()
			break
		}
	}
	err = scanner.Err()
	if err != io.EOF && err != nil {
		return
	}

	groups = groupStates(rs)
	diff = string(Difference(rs))
	diffRet = differenceReturns(returns)
	return
}
