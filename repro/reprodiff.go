package repro

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/config"
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
	executorBin, err := inst.Copy(filepath.Join(cfg.Syzkaller, "bin", "syz-executor.dbg"))
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
	command := fmt.Sprintf("%v -executor=%v -prog=%v -testfs=%v -log=%v -min",
		reproducer.reprodiffBin, reproducer.executorBin, vmProgFile, strings.Join(reproducer.cfg.Filesystems, ":"), vmLogFile)
	outc, errc, err := reproducer.inst.Run(time.Minute*30, reproducer.stop, command)
	if err != nil {
		return "", fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	if err := waitForExecution(outc, errc); err != nil {
		return "", fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	Logf(0, "executed command: %v", command)

	hostLog := filepath.Join(reproducer.logPath, fname+".log")
	if err := reproducer.inst.MoveOut(vmLogFile, hostLog); err != nil {
		return "", fmt.Errorf("failed to copy out log file: %v", err)
	}
	Logf(0, "copied out log file from vm: %v", vmLogFile)

	return hostLog, nil
}

func readProg(scanner *bufio.Scanner) (*prog.Prog, error) {
	var buf bytes.Buffer
	for scanner.Scan() && scanner.Text() != "" {
		if _, err := buf.WriteString(scanner.Text()); err != nil {
			return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
		}
		if _, err := buf.Write([]byte("\n")); err != nil {
			return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
		}
	}
	prog, err := prog.Deserialize(buf.Bytes())
	if err != nil || prog == nil || len(prog.Calls) == 0 {
		return nil, fmt.Errorf("failed to read prog from repro log: %v\n%s", err, buf.String())
	}
	return prog, err
}

func readStates(scanner *bufio.Scanner) ([]string, error) {
	states := []string{}
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Failed") {
			return nil, fmt.Errorf("failed to read states: %v", scanner.Text())
		}
		if !strings.HasPrefix(scanner.Text(), "###") {
			continue
		}
		st := ""
		for scanner.Scan() && scanner.Text() != "" {
			st += scanner.Text()
			st += "\n"
		}
		states = append(states, st)
	}
	return states, nil
}

var fieldNames = []string{"Perm", "Link", "User", "Group", "Size", "Name", "File"}

func compareState(s1 string, s2 string) []string {
	fields := make(map[int]bool)
	lines1 := strings.Split(s1, "\n")
	lines2 := strings.Split(s2, "\n")
	if len(lines1) != len(lines2) {
		fields[6] = true
	} else {

		for i, l1 := range lines1 {
			l2 := lines2[i]
			fields1 := strings.Split(l1, " ")
			fields2 := strings.Split(l2, " ")
			for i, f1 := range fields1 {
				if f1 != fields2[i] {
					fields[i] = true
				}
			}
		}
	}

	delta := []string{}
	for k := range fields {
		delta = append(delta, fieldNames[k])
	}
	return delta
}

func diffStates(states []string) ([]int, []string) {
	groups := make([]int, len(states))
	deltas := make([]string, len(states))
	group_id := make(map[string]int)

	for i, st := range states {
		if i == 0 {
			groups[0] = 0
			deltas[0] = ""
			group_id[states[0]] = 0
			continue
		}
		if id, ok := group_id[st]; ok {
			groups[i] = id
			deltas[i] = deltas[id]
		} else {
			delta := compareState(states[0], st)
			groups[i] = i
			deltas[i] = strings.Join(delta, ",")
		}
	}

	return groups, deltas
}

func ParseMinProg(log string) (*prog.Prog, error) {
	logFile, err := os.Open(log)
	defer logFile.Close()
	if err != nil {
		return nil, err
	}

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

func ParseStates(log string) (states []string, groups []int, deltas []string, err error) {
	var logFile *os.File
	logFile, err = os.Open(log)
	defer logFile.Close()
	if err != nil {
		return
	}

	//var states []string
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "## State") {
			states, err = readStates(scanner)
			if err != nil {
				return
			}
			break
		}
	}
	err = scanner.Err()
	if err != nil {
		return
	}
	if len(states) == 0 {
		err = fmt.Errorf("empty states")
		return
	}

	groups, deltas = diffStates(states)
	return
}
