package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

var (
	flagTestfs   = flag.String("testfs", "./", "a colon-separated list of test filesystems")
	flagLog      = flag.String("log", "repro.log", "reproducing log")
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagProg     = flag.String("prog", "", "diff-inducing program to reproduce")
	flagMinimize = flag.Bool("min", false, "minimize input program")
	flagSaveDir  = flag.Bool("save", false, "save working directory")
	testfs       []string
	logFile      *os.File
)

func initExecutor() (*ipc.Env, *os.File, error) {
	// FIXME: set flags, cover=0, threaded=0 collide=0
	var flags uint64
	timeout := 1 * time.Minute
	flags |= ipc.FlagRepro

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init executor: %v", err)
	}

	env, err := ipc.MakeEnv(*flagExecutor, timeout, flags, 0, writePipe)
	if err != nil {
		writePipe.Close()
		readPipe.Close()
		return nil, nil, fmt.Errorf("failed to init executor: %v", err)
	}

	return env, readPipe, nil
}

func execute1(env *ipc.Env, prog *prog.Prog) ([]*ipc.State, error) {
	// FIXME: error, failed, hanged?
	var states []*ipc.State
	for _, fs := range testfs {
		output, _, failed, hanged, err, state := env.Exec(prog, false, false, true, fs)
		states = append(states, state)
		if err != nil {
			Logf(0, "ERR: executor threw error: %s", err)
			return nil, err
		}

		if failed {
			Logf(0, "BUG: executor-detected bug:\n%s", output)
			return nil, fmt.Errorf("executor-detected failure")
		}
		if hanged {
			Logf(0, "HANG: executor hanged")
			return nil, fmt.Errorf("executor-detected hang")
		}
	}

	return states, nil
}

func parseInput(inputFile string) (*prog.Prog, error) {
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		return nil, err
	}

	p, err := prog.Deserialize(data)
	if err != nil {
		return nil, err
	}

	return p, nil
}

var header = "ReproDiff: %s\n=====================================\n"

func writeLog(template string, vargs ...interface{}) error {
	if logFile == nil {
		return fmt.Errorf("failed to write to log file")
	}

	str := fmt.Sprintf(template, vargs...)
	_, err := logFile.WriteString(str)
	if err != nil {
		logFile.Close()
		logFile = nil
		return fmt.Errorf("failed to write to log file")
	}
	return nil
}

func writeFsStates(workdirs []string) error {
	for i, dir := range workdirs {
		if err := writeLog("### %s\n", testfs[i]); err != nil {
			return err
		}
		cmd := fmt.Sprintf("cd %v; ls -lR . | grep -v 'total' | awk '{print $1, $2, $3, $4, $5, $9}'", filepath.Join(dir, "0"))
		out, err := exec.Command("bash", "-c", cmd).Output()
		if err != nil {
			return fmt.Errorf("failed to execute command %s: %v", cmd, err)
		}
		if err := writeLog("%s\n\n", out); err != nil {
			return err
		}
	}
	return nil
}

func writeRes(p *prog.Prog, states []*ipc.State) error {
	if err := writeLog("## Return values:\n"); err != nil {
		return err
	}

	for i, c := range p.Calls {
		if err := writeLog("%v ", c.Meta.Name); err != nil {
			return err
		}
		for _, st := range states {
			if err := writeLog("%d(%d) ", st.Res[i], st.Errnos[i]); err != nil {
				return err
			}
		}
		writeLog("\n")
	}
	writeLog("\n")
	return nil
}

func writeOutput(output []byte) error {
	if err := writeLog("## Logs:\n"); err != nil {
		return err
	}

	n, err := logFile.Write(output)
	if err != nil || n != len(output) {
		return err
	}

	return nil
}

func reproduce() error {
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	env, debug, err := initExecutor()
	defer func() {
		if env != nil {
			env.CloseWithoutRm()
		}
		if debug != nil {
			if err := writeLog("## Log:\n"); err != nil {
				return
			}
			// FIXME: TIMEOUT
			io.Copy(logFile, debug)
		}
	}()

	if err != nil {
		return err
	}

	p, err := parseInput(*flagProg)
	if err != nil {
		return err
	}

	if p == nil || len(p.Calls) == 0 {
		Logf(0, "received test program")
		if err := writeLog(header, "Test VM Passed"); err != nil {
			return err
		}
		return nil
	}

	Logf(0, "received program to reproduce: %s", p)
	if err := writeLog(header, filepath.Base(*flagProg)); err != nil {
		return err
	}
	if err := writeLog("## Prog: %s\n%s\n\n## State:\n", p, p.Serialize()); err != nil {
		return err
	}

	// execute program
	states, err := execute1(env, p)

	if err != nil {
		writeLog("Failed to execute program: %v\n\n", err)
		return err
	}
	// Check discrepancy
	if !ipc.CheckDiscrepancy(states) {
		writeLog("Failed to reproduce discrepancy: %v\n\n", err)
		return fmt.Errorf("failed to reproduce discrepancy")
	}
	Logf(0, "reproduced program %s", p)
	var workdirs []string
	for _, s := range states {
		workdirs = append(workdirs, s.Workdir)
	}
	defer func() {
		if *flagSaveDir {
			return
		}
		for _, dir := range workdirs {
			fileutil.UmountAll(dir)
			os.RemoveAll(dir)
		}
	}()

	if err := writeFsStates(workdirs); err != nil {
		return err
	}

	if err := writeRes(p, states); err != nil {
		return err
	}

	if !*flagMinimize {
		return nil
	}
	p1, _ := prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
		states, err := execute1(env, p1)
		if err != nil {
			// FIXME: how to compare in the existence of error/hang?
			Logf(0, "Execution threw error: %v", err)
			return false
		} else {
			cond := ipc.CheckDiscrepancy(states)
			return cond
		}
	}, false)

	// Test single-user case
	p2 := p1.Clone()
	prog.SetUser(p2, prog.U1)
	states, err = execute1(env, p2)
	if err != nil {
		return err
	}
	if ipc.CheckDiscrepancy(states) {
		p1 = p2
	}

	Logf(0, "minimized prog to %s", p1)
	err = writeLog("## Minimized Prog: %s\n%s\n\n", p1, p1.Serialize())
	if err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()
	if *flagProg == "" {
		Fatalf("Must specify a diff-inducing program to reproduce")
	}

	testfs = strings.Split(*flagTestfs, ":")
	if len(testfs) < 2 {
		Fatalf("Must specify two or more test filesystems")
	}

	var err error
	logFile, err = os.OpenFile(*flagLog, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		Fatalf("failed to create log file: %v", err)
	}

	if err := reproduce(); err != nil {
		Fatalf("Failed to reproduce: %s", err)
	}
}
