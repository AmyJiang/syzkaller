package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/syzkaller/diff"
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

func execute1(env *ipc.Env, prog *prog.Prog, targetfs []string) ([]*diff.ExecResult, error) {
	var rs []*diff.ExecResult
	for _, fs := range targetfs {
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

func writeStates(rs []*diff.ExecResult) error {
	// cmd := fmt.Sprintf("cd %v; ls -lR . | grep -v 'total' | awk '{print $1, $2, $3, $4, $5, $9}'", filepath.Join(dir, "0"))
	for _, r := range rs {
		if err := writeLog("### %s", r.FS); err != nil {
			return err
		}
		if err := writeLog("%s\n\n", r.State); err != nil {
			return err
		}
	}
	return nil
}

func writeRes(p *prog.Prog, rs []*diff.ExecResult) error {
	if err := writeLog("## Return values:\n"); err != nil {
		return err
	}

	for _, r := range rs {
		for i := 0; i < len(p.Calls); i++ {
			if err := writeLog("%d(%d) ", r.Res[i], r.Errnos[i]); err != nil {
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

func initExecutor() (env *ipc.Env, readPipe *os.File, err error) {
	var writePipe *os.File

	flags, timeout, _ := ipc.DefaultFlags()
	if flags&ipc.FlagDebug != 0 {
		readPipe, writePipe, err = os.Pipe()
		if err != nil {
			err = fmt.Errorf("failed to init executor: %v", err)
			return
		}

		dbgFile, err = os.OpenFile(*flagLog+".dbg", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			err = fmt.Errorf("failed to create log file: %v", err)
			return
		}
	}

	env, err = ipc.MakeEnv(*flagExecutor, timeout, ipc.FlagRepro|flags, 0, writePipe)
	if err != nil {
		if flags&ipc.FlagDebug != 0 {
			dbgFile.Close()
			writePipe.Close()
			readPipe.Close()
		}
		err = fmt.Errorf("failed to init executor: %v", err)
		return
	}

	return
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
		if debug != nil && dbgFile != nil {
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
	rs, err := execute1(env, p, testfs)
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
	diff_state = diff.CheckHash(rs)
	diff_return = diff.CheckReturns(rs)
	if !diff_state && !diff_return {
		return fmt.Errorf("failed to reproduce discrepancy")
	}

	// Start minimization
	if !*flagMinimize {
		return nil
	}

	var p1 *prog.Prog
	var d []string
	var targetfs []string
	targetfs = append(targetfs, testfs[0])
	// Minimize the program while keeping all original discrepancies
	// in filesystem states
	d = diff.Difference(rs, p, !diff_state)
	for i, r := range rs {
		if !reflect.DeepEqual(rs[0].StateHash, r.StateHash) {
			targetfs = append(targetfs, testfs[i])
		}
	}
	d = diff.Difference(rs, p, !diff_state)
	Logf(0, "Original Difference: %s", d)
	p1, _ = prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
		rs1, err := execute1(env, p1, targetfs)
		if err != nil {
			// FIXME: how to compare in the existence of error/hang?
			Logf(0, "Execution threw error: %v", err)
			return false
		} else {
			d1 := diff.Difference(rs1, p1, !diff_state)
			same := reflect.DeepEqual(d, d1)
			Logf(1, "%s(%v):\t%s", p1, same, d1)
			return same
		}
	}, false)

	// Try to minimize the program to single-user scenario
	p2 := p1.Clone()
	prog.SetUser(p2, prog.U1)
	rs2, err := execute1(env, p2, targetfs)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(d, diff.Difference(rs2, p2, !diff_state)) {
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

	if err := reproduce(); err != nil {
		logFile.Close()
		Fatalf("Failed to reproduce: %s", err)
	}
}
