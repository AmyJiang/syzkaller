package repro

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/config"
	. "github.com/google/syzkaller/log"
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

func (reproducer *DiffReproducer) Repro(fname string, p []byte) error {
	progFile := filepath.Join("/tmp", fname)
	os.Remove(progFile)
	if err := ioutil.WriteFile(progFile, p, 0666); err != nil {
		return fmt.Errorf("failed to create a temp file for diff prog: %v", err)
	}
	defer os.Remove(progFile)

	vmProgFile, err := reproducer.inst.CopyTo(progFile, "/tmp")
	if err != nil {
		return fmt.Errorf("failed to copy to VM: %v", err)
	}
	vmLogFile := filepath.Join("/tmp", fname+".log")
	command := fmt.Sprintf("%v -executor=%v -prog=%v -testfs=%v -log=%v",
		reproducer.reprodiffBin, reproducer.executorBin, vmProgFile, strings.Join(reproducer.cfg.Filesystems, ":"), vmLogFile)
	outc, errc, err := reproducer.inst.Run(time.Minute*30, reproducer.stop, command)
	if err != nil {
		return fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	if err := waitForExecution(outc, errc); err != nil {
		return fmt.Errorf("failed to run syz-reprodiff: %v", err)
	}
	Logf(0, "executed command: %v", command)

	if err := reproducer.inst.MoveOut(vmLogFile, reproducer.logPath); err != nil {
		return fmt.Errorf("failed to copy out log file: %v", err)
	}
	Logf(0, "copied out log file from vm: %v", vmLogFile)

	return nil
}
