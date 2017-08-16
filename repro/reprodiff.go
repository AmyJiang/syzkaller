package repro

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

type DiffReproducer struct {
	inst         vm.Instance
	cfg          *config.Config
	reprodiffBin string
	executorBin  string
	stop         <-chan bool
	logPath      string
}

func CreateDiffReproducer(idx int, stop <-chan bool, cfg *config.Config) (*DiffReproducer, error) {
	vmCfg, err := config.CreateVMConfig(cfg, idx)
	if err != nil {
		return nil, err
	}
	inst, err := vm.Create(cfg.Type, vmCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create diff VM: %v", err)
	}
	reprodiffBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin", "syz-reprodiff"))
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}
	executorBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin", "syz-executor"))
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	logPath := filepath.Join(cfg.Workdir, "logs")
	if err := os.Mkdir(logPath, 0777); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("failed to create logs/ in working directory: %v", err)
	}

	return &DiffReproducer{
		inst:         inst,
		cfg:          cfg,
		stop:         stop,
		reprodiffBin: reprodiffBin,
		executorBin:  executorBin,
		logPath:      logPath,
	}, nil
}

func (reproducer *DiffReproducer) Close() error {
	command := fmt.Sprintf("rm -rf %v %v",
		reproducer.reprodiffBin, reproducer.executorBin)
	_, _, err := reproducer.inst.Run(time.Minute*3, reproducer.stop, command)
	if err != nil {
		return fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	reproducer.inst.Close()
	return nil
}

func waitForExecution(outc <-chan []byte, errc <-chan error) error {
	err := <-errc
	switch err {
	case nil:
		// The program has exited without errors,
		return nil
	case vm.TimeoutErr:
		return err
	default:
		return fmt.Errorf("lost connection to diff reproducer VM")
	}
}

func (reproducer *DiffReproducer) Repro(fname string, p []byte) (string, error) {
	progFile := filepath.Join("/tmp", fname)
	os.Remove(progFile)
	if err := ioutil.WriteFile(progFile, p, 0666); err != nil {
		return "", fmt.Errorf("failed to create a temp file for diff prog: %v", err)
	}
	defer os.Remove(progFile)

	vmProgFile, err := reproducer.inst.CopyTo(progFile, "/tmp")
	if err != nil {
		return "", fmt.Errorf("failed to copy to VM: %v", err)
	}
	vmLogFile := filepath.Join("/tmp", fname+".log")
	command := fmt.Sprintf("%v -executor=%v -prog=%v -testfs=%v -log=%v -debug -min",
		reproducer.reprodiffBin, reproducer.executorBin, vmProgFile, strings.Join(reproducer.cfg.Filesystems, ":"), vmLogFile)
	Logf(0, "executing command: %v", command)
	outc, errc, err := reproducer.inst.Run(time.Minute*30, reproducer.stop, command)
	if err != nil {
		return "", fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	if err := waitForExecution(outc, errc); err != nil {
		return "", fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}

	hostLog := filepath.Join(reproducer.logPath, fname+".log")
	if err := reproducer.inst.MoveOut(vmLogFile, hostLog); err != nil {
		return "", fmt.Errorf("failed to copy out log file: %v", err)
	}
	if err := reproducer.inst.MoveOut(vmLogFile+".dbg", hostLog+".dbg"); err != nil {
		return "", fmt.Errorf("failed to copy out log file: %v", err)
	}

	Logf(0, "copied out log file from vm: %v", vmLogFile)

	return hostLog, nil
}

func readProg(scanner *bufio.Scanner) (*prog.Prog, error) {
	var buf bytes.Buffer
	for scanner.Scan() && scanner.Text() != "" {
		if _, err := buf.WriteString(scanner.Text() + "\n"); err != nil {
			return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
		}
		/*		if _, err := buf.WriteString("\n"); err != nil {
					return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
				}
		*/
	}
	prog, err := prog.Deserialize(buf.Bytes())
	if err != nil || prog == nil || len(prog.Calls) == 0 {
		return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
	}
	return prog, nil
}

func readStates(scanner *bufio.Scanner) ([]*ipc.ExecResult, error) {
	var rs []*ipc.ExecResult
	var r *ipc.ExecResult

	for scanner.Scan() && !strings.HasPrefix(scanner.Text(), "## ") {
		if strings.HasPrefix(scanner.Text(), "Failed") {
			return nil, fmt.Errorf("%s", scanner.Text())
		}
		if strings.HasPrefix(scanner.Text(), "###") {
			r = &ipc.ExecResult{
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

func groupStates(rs []*ipc.ExecResult) (groups []int) {
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
		ret := strings.Fields(l)[1:]
		if !reflect.DeepEqual(ret[:len(ret)-1], ret[1:]) {
			return l
		}
	}
	return ""
}

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

func ParseReproLog(log string) (name string, groups []int, diff string, diffRet string, err error) {
	var logFile *os.File
	logFile, err = os.Open(log)
	if err != nil {
		return
	}
	defer logFile.Close()

	var rs []*ipc.ExecResult
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
