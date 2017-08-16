package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

var (
	flagTestfs   = flag.String("testfs", "./", "a colon-separated list of test filesystems")
	flagLog      = flag.String("log", "repro.log", "summary of reproduction and(or) minimization")
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagProg     = flag.String("prog", "", "diff-inducing program to reproduce")
	flagMinimize = flag.Bool("min", false, "minimize input program")
	flagSaveDir  = flag.Bool("save", false, "save working directory")
	testfs       []string
	logFile      *os.File
	dbgFile      *os.File
)

func execute1(env *ipc.Env, prog *prog.Prog) ([]*ipc.ExecResult, error) {
	var rs []*ipc.ExecResult
	for _, fs := range testfs {
		output, _, failed, hanged, err, r := env.Exec(prog, false, false, true, fs)
		rs = append(rs, r)
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

	return rs, nil
}

func parseInput(inputFile string) (p *prog.Prog, err error) {
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		return
	}
	p, err = prog.Deserialize(data)
	if err != nil {
		return
	}
	return
}

var header = "ReproDiff: %s\n=====================================\n"

func writeLog(template string, vargs ...interface{}) error {
	if logFile == nil {
		return fmt.Errorf("failed to write to log file")
	}

	str := fmt.Sprintf(template, vargs...)
	if _, err := logFile.WriteString(str); err != nil {
		return fmt.Errorf("failed to write to log file")
	}
	return nil
}

func writeStates(rs []*ipc.ExecResult) error {
	// cmd := fmt.Sprintf("cd %v; ls -lR . | grep -v 'total' | awk '{print $1, $2, $3, $4, $5, $9}'", filepath.Join(dir, "0"))
	for _, r := range rs {
		if err := writeLog("### %s", strings.Split(r.FS, "/")[1]); err != nil {
			return err
		}
		if err := writeLog("%s\n\n", r.State); err != nil {
			return err
		}
	}
	return nil
}

func writeRes(p *prog.Prog, rs []*ipc.ExecResult) error {
	if err := writeLog("## Return values:\n"); err != nil {
		return err
	}

	for i, c := range p.Calls {
		if err := writeLog("%v ", c.Meta.Name); err != nil {
			return err
		}
		for _, st := range rs {
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

// diffState returns a description of differences between the states of two file systems.
var diffType = [][]byte{
	[]byte("Name"), []byte("Mode"), []byte("Uid"), []byte("Gid"), []byte("Link"), []byte("Size")}

func diffState(s0 []byte, s []byte) (diff []byte) {
	files := bytes.Split(s, []byte{'\n'})[1:]
	files0 := bytes.Split(s0, []byte{'\n'})[1:]
	if len(files) != len(files0) {
		diff = append(diff, "File-Num "...)
		return
	}
	for i, _ := range files {
		fields := bytes.Fields(files[i])
		fields0 := bytes.Fields(files0[i])
		for j, _ := range fields {
			if !reflect.DeepEqual(fields[j], fields0[j]) {
				diff = append(diff, fmt.Sprintf("%s-%s ", fields[0], diffType[j])...)
			}
		}
	}
	return
}

func difference(rs []*ipc.ExecResult) []byte {
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

func initExecutor() (*ipc.Env, *os.File, error) {
	var flags uint64
	flags = ipc.FlagRepro | ipc.FlagDebug
	timeout := 3 * time.Minute

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

func reproduce() error {
	var env *ipc.Env
	var debug *os.File
	var err error

	env, debug, err = initExecutor()
	if err != nil {
		return err
	}
	if *flagSaveDir {
		defer env.CloseWithoutRm()
	} else {
		defer env.Close()
	}

	const BufSize int64 = 8 << 20
	go func() {
		if dbgFile != nil {
			for {
				_, err := io.CopyN(dbgFile, debug, BufSize)
				if err != nil {
					break
				}
			}
			dbgFile.Close()
		}
	}()

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
	rs, err := execute1(env, p)
	if err != nil {
		writeLog("Failed to execute program: %v\n\n", err)
		return err
	}
	Logf(0, "reproduced program %s", p)

	if err := writeStates(rs); err != nil {
		return err
	}
	if err := writeRes(p, rs); err != nil {
		return err
	}

	// Check for discrepancy in filesystem states and syscall return values
	var diff_state, diff_return bool
	diff_state = ipc.CheckHash(rs)
	diff_return = ipc.CheckReturns(rs)
	if !diff_state && !diff_return {
		writeLog("\nFailed to reproduce discrepancy: %v\n\n", err)
		return fmt.Errorf("failed to reproduce discrepancy")
	}

	// Start minimization
	if !*flagMinimize {
		return nil
	}

	var p1 *prog.Prog
	var diff []byte
	if diff_state {
		// Minimize the program while keeping all original discrepancies
		// in filesystem states
		diff = difference(rs)
		p1, _ = prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
			rs1, err := execute1(env, p1)
			if err != nil {
				// FIXME: how to compare in the existence of error/hang?
				Logf(0, "Execution threw error: %v", err)
				return false
			} else {
				return reflect.DeepEqual(diff, difference(rs1))
			}
		}, false)
	} else {
		p1, _ = prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
			rs1, err := execute1(env, p1)
			if err != nil {
				// FIXME: how to compare in the existence of error/hang?
				Logf(0, "Execution threw error: %v", err)
				return false
			} else {
				return ipc.CheckReturns(rs1)
			}
		}, false)
	}

	// Try to minimize the program to single-user scenario
	p2 := p1.Clone()
	prog.SetUser(p2, prog.U1)
	rs2, err := execute1(env, p2)
	if err != nil {
		return err
	}
	if diff_state && reflect.DeepEqual(diff, difference(rs2)) || ipc.CheckReturns(rs2) {
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
	var err error

	flag.Parse()
	if *flagProg == "" {
		Fatalf("Must specify a diff-inducing program to reproduce")
	}

	testfs = strings.Split(*flagTestfs, ":")
	if len(testfs) < 2 {
		Fatalf("Must specify two or more test filesystems")
	}

	if *flagLog == "" {
		Fatalf("Must specify a log file for reproduction/minimization summary")
	}
	logFile, err = os.OpenFile(*flagLog, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		Fatalf("failed to create log file: %v", err)
	}
	defer logFile.Close()

	dbgFile, err = os.OpenFile(*flagLog+".dbg", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		logFile.Close()
		Fatalf("failed to create log file: %v", err)
	}
	defer dbgFile.Close()

	if err := reproduce(); err != nil {
		logFile.Close()
		dbgFile.Close()
		Fatalf("Failed to reproduce: %s", err)
	}
}
