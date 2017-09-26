package diff

import (
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

// DiffReproducer reproduces the found discrepancy-inducing programs
// in a different VM. It outputs a reproducing log to workdir/logs
type DiffReproducer struct {
	inst         vm.Instance
	cfg          *config.Config
	reprodiffBin string
	executorBin  string
	stop         <-chan bool
	logPath      string
}

type DiffRepro struct {
	Sig     string
	Prog    []byte
	MinProg *prog.Prog
	Log     string
	Err     error
}

// CreateDiffReproducer setups a diff reproducer.
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

	// Setup test filesystems
	_, _, err = inst.Run(time.Minute, stop, fmt.Sprintf("chmod 777 %v", strings.Join(cfg.Filesystems, " ")))
	if err != nil {
		return nil, fmt.Errorf("failed to setup test filesystems: %v", err)
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

// Close closes the diff reproducer and the underlying VM.
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
		return fmt.Errorf("lost connection to diff reproducer VM: %v", err)
	}
}

// Repro reproduces a diff-inducing program.
func (reproducer *DiffReproducer) Repro(sig string, p []byte) *DiffRepro {
	// Copy in the program to reproduce
	// FIXME: copyin too slow! Can it be implemented with RPC?
	progFile := filepath.Join("/tmp", sig)
	os.Remove(progFile)
	if err := ioutil.WriteFile(progFile, p, 0666); err != nil {
		return &DiffRepro{sig, p, nil, "", fmt.Errorf("failed to create a temp file for diff prog: %v", err)}
	}
	defer os.Remove(progFile)

	vmProgFile, err := reproducer.inst.CopyTo(progFile, "/tmp")
	if err != nil {
		return &DiffRepro{sig, p, nil, "", fmt.Errorf("failed to copy to VM: %v", err)}
	}

	// Run the syz-reprodiff tool in VM for the program
	vmLogFile := filepath.Join("/tmp", sig+".log")
	command := fmt.Sprintf("%v -executor=%v -prog=%v -testfs=%v -log=%v -debug -min -v -1",
		reproducer.reprodiffBin, reproducer.executorBin, vmProgFile, strings.Join(reproducer.cfg.Filesystems, ":"), vmLogFile)

	// FIXME: retry for ssh connection EOF
	for try := 0; try < 3; try++ {
		Logf(0, "executing command: %v (%v/3)", command, try)
		if try > 0 {
			time.Sleep(time.Second)
		}
		outc, errc, err := reproducer.inst.Run(time.Minute*30, reproducer.stop, command)
		if err != nil {
			continue
		}

		if err := waitForExecution(outc, errc); err != nil {
			continue
		}

		hostLog := filepath.Join(reproducer.logPath, sig+".log")
		if err := reproducer.inst.MoveOut(vmLogFile, hostLog); err != nil {
			continue
		}

		Logf(0, "copied out log file from vm: %v", vmLogFile)
		minProg, err := ParseMinProg(hostLog)
		return &DiffRepro{sig, p, minProg, hostLog, err}
	}

	return &DiffRepro{sig, p, nil, "", fmt.Errorf("failed to run syz-reprodiff on diff vm")}
}
