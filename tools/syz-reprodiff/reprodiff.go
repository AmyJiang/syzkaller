package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

var (
	flagTestfs   = flag.String("testfs", "./", "a colon-separated list of test filesystems")
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagProg     = flag.String("prog", "", "diff-inducing program to reproduce")
	flagMinimize = flag.Bool("min", false, "minimize input program")
	testfs       []string
)

func initExecutor() (*ipc.Env, error) {
	// FIXME: set flags, cover=0, threaded=0 collide=0
	var flags uint64
	flags |= ipc.FlagDebug

	timeout := 1 * time.Minute
	env, err := ipc.MakeEnv(*flagExecutor, timeout, flags, 0)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func execute1(env *ipc.Env, prog *prog.Prog) ([][]uint32, error) {
	// FIXME: error, failed, hanged?
	states := make([][]uint32, len(testfs))
	for i, dir := range testfs {
		output, _, failed, hanged, err, state := env.Exec(prog, false, false, true, dir)
		states[i] = append(states[i], state...)
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

func isDiscrepancy(states [][]uint32) bool {
	for i := 1; i < len(states); i += 1 {
		// FIXME: executor fails before handle_completion
		if len(states[i]) != len(states[i-1]) {
			break
		}
		for j, v := range states[i-1] {
			if v != states[i][j] {
				return true
			}
		}
	}
	return false
}

func reproduce() error {
	env, err := initExecutor()
	defer env.CloseWithoutRm()

	if err != nil {
		return err
	}

	p, err := parseInput(*flagProg)
	if err != nil {
		return err
	}

	states, err := execute1(env, p)
	if err != nil {
		return err
	}

	if !isDiscrepancy(states) {
		return fmt.Errorf("failed to reproduce discrepancy")
	}

	if !*flagMinimize {
		return nil
	}

	p1, _ := prog.Minimize(p, -1, func(p1 *prog.Prog, call1 int) bool {
		states, err := execute1(env, p1)
		if err != nil {
			// FIXME: how to compare in the existence of error/hang?
			return false
		} else {
			return isDiscrepancy(states)
		}
	}, false)

	Logf(0, "Minimized prog: %s", p1)
	if err := writeFile(*flagProg+".min", p1.Serialize()); err != nil {
		return err
	}

	return nil
}

func writeFile(outf string, data []byte) error {
	err := ioutil.WriteFile(outf, data, 0666)
	return err
}

func main() {
	flag.Parse()
	if *flagProg == "" {
		Fatalf("Must specify a diff-inducing program to reproduce")
		os.Exit(1)
	}

	testfs = strings.Split(*flagTestfs, ":")
	if len(testfs) < 2 {
		Fatalf("Must specify two or more test filesystems")
		os.Exit(1)
	}

	Logf(0, "Test directories: %v", testfs)

	if err := reproduce(); err != nil {
		Fatalf("Failed to reproduce: %s", err)
	}
}
