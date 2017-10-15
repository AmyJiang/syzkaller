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
	flagDbgFile  = flag.String("dbg", "debug.log", "")
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagProg     = flag.String("prog", "", "diff-inducing program to reproduce")
	flagProgDir  = flag.String("dir", "", "directory of programs to reproduce")
	flagMinimize = flag.Bool("min", false, "minimize input program")
	flagSaveDir  = flag.Bool("save", false, "save working directory")
	flagRetvals  = flag.Bool("ret", false, "check difference in return values")
	testfs       []string
	dbgFile      *os.File
	logFile      *os.File
)

func execute1(env *ipc.Env, prog *prog.Prog, targetfs []string) ([]*diff.ExecResult, error) {
	var rs []*diff.ExecResult
	for _, fs := range targetfs {
		output, _, failed, hanged, err, r := env.Exec(prog, false, false, true, fs)
		rs = append(rs, r)
		if err != nil {
			Logf(0, "ERR: executor threw error")
			return nil, fmt.Errorf("executor throw error:%s", err)
		}
		if failed {
			Logf(0, "BUG: executor-detected bug")
			return nil, fmt.Errorf("executor-detected failure:%s", output)
		}
		if hanged {
			Logf(0, "HANG: executor hanged")
			return nil, fmt.Errorf("executor-detected hang")
		}
	}

	return rs, nil
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
	var err error
	err = writeLog("## Return values:\n")
	if err != nil {
		return err
	}

	for _, r := range rs {
		for i := 0; i < len(p.Calls); i++ {
			if len(r.Res) <= i || len(r.Errnos) <= i {
				err = writeLog("nil(nil) ")
			} else {
				err = writeLog("%d(%d) ", r.Res[i], r.Errnos[i])
			}

			if err != nil {
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

		dbgFile, err = os.OpenFile(*flagDbgFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
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

func parseInput(input string) (p *prog.Prog, err error) {
	data, err := ioutil.ReadFile(input)
	if err != nil {
		return
	}
	p, err = prog.Deserialize(data)
	if err != nil {
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

	var inputs []string
	if *flagProgDir != "" {
		files, err := ioutil.ReadDir(*flagProgDir)
		if err != nil {
			return err
		}
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".log") || file.Name() == "." || file.Name() == ".." {
				continue
			}
			inputs = append(inputs, filepath.Join(*flagProgDir, file.Name()))
		}
	} else {
		inputs = append(inputs, *flagProg)
	}

	for _, file := range inputs {
		var p *prog.Prog
		Logf(0, "Prog: %s", file)
		p, err = parseInput(file)
		if err != nil {
			return err
		}
		logFile, err = os.OpenFile(file+".log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			return fmt.Errorf("failed to create log file: %v", err)
		}
		defer logFile.Close()

		if p == nil || len(p.Calls) == 0 {
			Logf(0, "received test program")
			if err := writeLog(header, "Test VM Passed"); err != nil {
				return err
			}
		}

		Logf(0, "received program to reproduce: %s", p)
		if err := writeLog(header, filepath.Base(file)); err != nil {
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
		diff_return = *flagRetvals && diff.CheckReturns(rs)
		if !diff_state && !diff_return {
			writeLog("## Failed to reproduce discrepancy\n")
			Logf(0, "failed to reproduce discrepancy")
			continue
		}

		// Start minimization
		if !*flagMinimize {
			continue
		}

		var p1 *prog.Prog
		var d map[string]string
		// Minimize the program while keeping all original discrepancies
		// in filesystem states
		Logf(0, "diff_state:%v diff_return:%v", diff_state, diff_return)
		d = diff.Hash(diff.Difference(rs, p, diff.DiffTypes, !diff_state))
		Logf(0, "Original Difference: %s", d)
		p1, _ = prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
			if len(p1.Calls) == 0 {
				return false
			}
			rs1, err := execute1(env, p1, testfs)
			if err != nil {
				// FIXME: how to compare in the existence of error/hang?
				Logf(0, "%s: execution threw error", p1)
				return false
			} else {
				// a bug?
				d1 := diff.Hash(diff.Difference(rs1, p1, diff.DiffTypes, !diff_state))
				same := (d == d1)
				Logf(1, "%s(%v):\t%s", p1, same, d1)
				return same
			}
		}, false)

		// Try to minimize the program to single-user scenario
		p2 := p1.Clone()
		prog.SetUser(p2, prog.U1)
		rs2, err := execute1(env, p2, testfs)
		if err != nil {
			return err
		}
		if reflect.DeepEqual(d, diff.Difference(rs2, p2, diff.DiffTypes, !diff_state)) {
			p1 = p2
		}

		Logf(0, "minimized prog to %s", p1)
		err = writeLog("## Minimized Prog: %s\n%s\n\n", p1, p1.Serialize())
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	flag.Parse()
	if *flagProg == "" && *flagProgDir == "" {
		Fatalf("Must specify diff-inducing program(s) to reproduce")
	}

	testfs = strings.Split(*flagTestfs, ":")
	if len(testfs) < 2 {
		Fatalf("Must specify two or more test filesystems")
	}

	if err := reproduce(); err != nil {
		Fatalf("Failed to reproduce: %s", err)
	}
}
