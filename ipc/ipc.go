// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/diff"
	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/prog"
)

type Env struct {
	In  []byte
	Out []byte

	cmds      map[string]*command
	cmd       *command
	inFile    *os.File
	outFile   *os.File
	bin       []string
	timeout   time.Duration
	flags     uint64
	pid       int
	debugFile *os.File

	StatExecs    uint64
	StatRestarts uint64
}

const (
	FlagDebug            = uint64(1) << iota // debug output from executor
	FlagSignal                               // collect feedback signals (coverage)
	FlagThreaded                             // use multiple threads to mitigate blocked syscalls
	FlagCollide                              // collide syscalls to provoke data races
	FlagSandboxSetuid                        // impersonate nobody user
	FlagSandboxNamespace                     // use namespaces for sandboxing
	FlagEnableTun                            // initialize and use tun in executor
	FlagRepro

	outputSize   = 16 << 20
	signalOffset = 15 << 20

	statusFail  = 67
	statusError = 68
	statusRetry = 69
)

var (
	flagThreaded = flag.Bool("threaded", false, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", false, "collide syscalls to provoke data races")
	flagSignal   = flag.Bool("cover", true, "collect feedback signals (coverage)")
	flagSandbox  = flag.String("sandbox", "setuid", "sandbox for fuzzing (none/setuid/namespace)")
	flagDebug    = flag.Bool("debug", false, "debug output from executor")
	// Executor protects against most hangs, so we use quite large timeout here.
	// Executor can be slow due to global locks in namespaces and other things,
	// so let's better wait than report false misleading crashes.
	flagTimeout = flag.Duration("timeout", 1*time.Minute, "execution timeout")
)

// ExecutorFailure is returned from MakeEnv or from env.Exec when executor terminates by calling fail function.
// This is considered a logical error (a failed assert).
type ExecutorFailure string

func (err ExecutorFailure) Error() string {
	return string(err)
}

func DefaultFlags() (uint64, time.Duration, error) {
	var flags uint64
	if *flagThreaded {
		flags |= FlagThreaded
	}
	if *flagCollide {
		flags |= FlagCollide
	}
	if *flagSignal {
		flags |= FlagSignal
	}
	switch *flagSandbox {
	case "none":
	case "setuid":
		flags |= FlagSandboxSetuid
	case "namespace":
		flags |= FlagSandboxNamespace
	default:
		return 0, 0, fmt.Errorf("flag sandbox must contain one of none/setuid/namespace")
	}
	if *flagDebug {
		flags |= FlagDebug
	}
	return flags, *flagTimeout, nil
}

func MakeEnv(bin string, timeout time.Duration, flags uint64, pid int, debugFile *os.File) (*Env, error) {
	// IPC timeout must be larger then executor timeout.
	// Otherwise IPC will kill parent executor but leave child executor alive.
	if timeout < 7*time.Second {
		timeout = 7 * time.Second
	}
	inf, inmem, err := createMapping(prog.ExecBufferSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if inf != nil {
			closeMapping(inf, inmem)
		}
	}()
	outf, outmem, err := createMapping(outputSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if outf != nil {
			closeMapping(outf, outmem)
		}
	}()
	for i := 0; i < 8; i++ {
		inmem[i] = byte(flags >> (8 * uint(i)))
	}
	*(*uint64)(unsafe.Pointer(&inmem[8])) = uint64(pid)
	inmem = inmem[16:]
	env := &Env{
		In:        inmem,
		Out:       outmem,
		inFile:    inf,
		outFile:   outf,
		bin:       strings.Split(bin, " "),
		timeout:   timeout,
		flags:     flags,
		pid:       pid,
		debugFile: debugFile,
	}
	if len(env.bin) == 0 {
		return nil, fmt.Errorf("binary is empty string")
	}
	env.bin[0], err = filepath.Abs(env.bin[0]) // we are going to chdir
	if err != nil {
		return nil, fmt.Errorf("filepath.Abs failed: %v", err)
	}
	// Append pid to binary name.
	// E.g. if binary is 'syz-executor' and pid=15,
	// we create a link from 'syz-executor15' to 'syz-executor' and use 'syz-executor15' as binary.
	// This allows to easily identify program that lead to a crash in the log.
	// Log contains pid in "executing program 15" and crashes usually contain "Comm: syz-executor15".
	base := filepath.Base(env.bin[0])
	pidStr := fmt.Sprint(pid)
	if len(base)+len(pidStr) >= 16 {
		// TASK_COMM_LEN is currently set to 16
		base = base[:15-len(pidStr)]
	}
	binCopy := filepath.Join(filepath.Dir(env.bin[0]), base+pidStr)
	if err := os.Link(env.bin[0], binCopy); err == nil {
		env.bin[0] = binCopy
	}
	inf = nil
	outf = nil
	return env, nil
}

func (env *Env) CloseWithoutRm() error {
	for _, cmd := range env.cmds {
		if cmd != nil {
			cmd.closeWithoutRemove()
		}
	}

	env.debugFile.Close()
	err1 := closeMapping(env.inFile, env.In)
	err2 := closeMapping(env.outFile, env.Out)
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

func (env *Env) Close() error {
	for _, cmd := range env.cmds {
		if cmd != nil {
			cmd.close()
		}
	}

	env.debugFile.Close()
	err1 := closeMapping(env.inFile, env.In)
	err2 := closeMapping(env.outFile, env.Out)
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

type CallInfo struct {
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	//if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Errno int
}

// Exec starts executor binary to execute program p and returns information about the execution:
// output: process output
// info: per-call info
// failed: true if executor has detected a kernel bug
// hanged: program hanged and was killed
// err0: failed to start process, or executor has detected a logical error
func (env *Env) Exec(p *prog.Prog, cover, dedup, needFsState bool, rootDir string) (output []byte, info []CallInfo, failed, hanged bool, err0 error, r *diff.ExecResult) {

	if p != nil {
		// Copy-in serialized program.
		if err := p.SerializeForExec(env.In, env.pid); err != nil {
			err0 = fmt.Errorf("executor %v: failed to serialize: %v", env.pid, err)
			return
		}
	}
	if env.flags&FlagSignal != 0 {
		// Zero out the first two words (ncmd and nsig), so that we don't have garbage there
		// if executor crashes before writing non-garbage there.
		for i := 0; i < 4; i++ {
			env.Out[i] = 0
		}
	}

	atomic.AddUint64(&env.StatExecs, 1)
	if env.cmds == nil {
		env.cmds = make(map[string]*command)
	}
	if cmd, ok := env.cmds[rootDir]; !ok || cmd == nil {
		if cmd == nil {
			atomic.AddUint64(&env.StatRestarts, 1)
		}
		env.cmds[rootDir], err0 = makeCommand(env.pid, env.bin, env.timeout, env.flags, env.inFile, env.outFile, rootDir, env.debugFile)
		if err0 != nil {
			return
		}
	}

	var restart bool
	output, failed, hanged, restart, err0 = env.cmds[rootDir].exec(cover, dedup, needFsState)
	if err0 != nil || restart {
		env.cmds[rootDir].close()
		env.cmds[rootDir] = nil
		return
	}

	if p == nil {
		return
	}

	if env.flags&FlagSignal != 0 || needFsState {
		info, err0, r = env.readOutResult(p, needFsState)
		if err0 != nil {
			return
		}
		if needFsState {
			r.FS = env.cmds[rootDir].dir
		}
	}

	return
}

func (env *Env) readOutResult(p *prog.Prog, needFsState bool) (info []CallInfo, err0 error, r *diff.ExecResult) {
	out := ((*[1 << 28]uint32)(unsafe.Pointer(&env.Out[0])))[:len(env.Out)/int(unsafe.Sizeof(uint32(0)))]
	readOut := func(v *uint32) bool {
		if len(out) == 0 {
			return false
		}
		*v = out[0]
		out = out[1:]
		return true
	}

	info = nil
	err0 = nil
	var ncmd uint32
	if !readOut(&ncmd) {
		err0 = fmt.Errorf("executor %v: failed to read output coverage", env.pid)
		return
	}

	var stateOffset uint32
	if !readOut(&stateOffset) {
		err0 = fmt.Errorf("executor %v: failed to read filesystem state", env.pid)
		return
	}

	if needFsState {
		r = &diff.ExecResult{
			FS:        "",
			Res:       []int32{},
			Errnos:    []int32{},
			State:     []byte{},
			StateHash: [20]byte{},
		}
	}

	info = make([]CallInfo, len(p.Calls))
	dumpCov := func() string {
		buf := new(bytes.Buffer)
		for i, inf := range info {
			str := "nil"
			if inf.Signal != nil {
				str = fmt.Sprint(len(inf.Signal))
			}
			fmt.Fprintf(buf, "%v:%v|", i, str)
		}
		return buf.String()
	}
	for i := uint32(0); i < ncmd; i++ {
		var callIndex, callNum, res, errno, signalSize, coverSize uint32
		if !readOut(&callIndex) || !readOut(&callNum) || !readOut(&res) || !readOut(&errno) || !readOut(&signalSize) || !readOut(&coverSize) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage", env.pid)
			return
		}
		if int(callIndex) >= len(info) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v, call %v (cov: %v)",
				env.pid, i, callIndex, len(info), ncmd, dumpCov())
			return
		}
		c := p.Calls[callIndex]
		if num := c.Meta.ID; uint32(num) != callNum {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v call %v: expect syscall %v, got %v, executed %v (cov: %v)",
				env.pid, i, callIndex, num, callNum, ncmd, dumpCov())
			return
		}
		if info[callIndex].Signal != nil {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: double coverage for call %v (cov: %v)",
				env.pid, callIndex, dumpCov())
			return
		}
		info[callIndex].Errno = int(errno)
		if needFsState {
			r.Res = append(r.Res, int32(res))
			r.Errnos = append(r.Errnos, int32(errno))
		}

		if signalSize > uint32(len(out)) {
			err0 = fmt.Errorf("executor %v: failed to read output signal: record %v, call %v, signalsize=%v coversize=%v",
				env.pid, i, callIndex, signalSize, coverSize)
			return
		}
		info[callIndex].Signal = out[:signalSize:signalSize]
		out = out[signalSize:]
		if coverSize > uint32(len(out)) {
			err0 = fmt.Errorf("executor %v: failed to read output coverage: record %v, call %v, signalsize=%v coversize=%v",
				env.pid, i, callIndex, signalSize, coverSize)
			return
		}
		info[callIndex].Cover = out[:coverSize:coverSize]
		out = out[coverSize:]
	}

	if needFsState {
		var stateSize uint32
		if !readOut(&stateSize) {
			err0 = fmt.Errorf("executor %v: failed to read filesystem state", env.pid)
			return
		}
		if stateSize > uint32(len(out)) {
			err0 = fmt.Errorf("executor %v: failed to read filesystem state: size=%v", env.pid, stateSize)
			return
		}

		r.State = make([]byte, stateSize*4)
		for i, v := range out[:stateSize] {
			binary.LittleEndian.PutUint32(r.State[i*4:], v)
		}
		r.StateHash = sha1.Sum(r.State)
		out = out[stateSize:]
	}

	return
}

func createMapping(size int) (f *os.File, mem []byte, err error) {
	// TODO (check if directory here is oK?)
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}
	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()
	fname := f.Name()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, 0)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fname)
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		err = fmt.Errorf("failed to mmap shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	return
}

func closeMapping(f *os.File, mem []byte) error {
	err1 := syscall.Munmap(mem)
	err2 := f.Close()
	err3 := os.Remove(f.Name())
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}

type command struct {
	pid      int
	timeout  time.Duration
	cmd      *exec.Cmd
	flags    uint64
	dir      string
	readDone chan []byte
	inrp     *os.File
	outwp    *os.File
}

func makeCommand(pid int, bin []string, timeout time.Duration, flags uint64, inFile *os.File, outFile *os.File, rootDir string, debugFile *os.File) (*command, error) {
	dir, err := ioutil.TempDir(rootDir, "syzkaller-testdir")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	c := &command{
		pid:     pid,
		timeout: timeout,
		flags:   flags,
		dir:     dir,
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()

	if true || flags&(FlagSandboxSetuid|FlagSandboxNamespace) != 0 {
		if err := os.Chmod(dir, 0777); err != nil {
			return nil, fmt.Errorf("failed to chmod temp dir: %v", err)
		}
	}

	// Output capture pipe.
	rp, wp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wp.Close()

	// Input command pipe.
	inrp, inwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer inwp.Close()
	c.inrp = inrp

	// Output command pipe.
	outrp, outwp, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer outrp.Close()
	c.outwp = outwp

	c.readDone = make(chan []byte, 1)

	cmd := exec.Command(bin[0], bin[1:]...)
	cmd.ExtraFiles = []*os.File{inFile, outFile, outrp, inwp}
	cmd.Env = []string{}
	cmd.Dir = dir
	if flags&FlagDebug == 0 {
		cmd.Stdout = wp
		cmd.Stderr = wp
		go func(c *command) {
			// Read out output in case executor constantly prints something.
			const BufSize = 128 << 10
			output := make([]byte, BufSize)
			size := 0
			for {
				n, err := rp.Read(output[size:])
				if n > 0 {
					size += n
					if size >= BufSize*3/4 {
						copy(output, output[size-BufSize/2:size])
						size = BufSize / 2
					}
				}
				if err != nil {
					rp.Close()
					c.readDone <- output[:size]
					close(c.readDone)
					return
				}
			}
		}(c)
	} else {
		close(c.readDone)
		cmd.Stdout = debugFile //os.Stdout
		cmd.Stderr = debugFile //os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start executor binary: %v", err)
	}
	c.cmd = cmd
	wp.Close()
	inwp.Close()
	if err := c.waitServing(); err != nil {
		return nil, err
	}

	tmp := c
	c = nil // disable defer above
	return tmp, nil
}

func (c *command) close() {
	if c.cmd != nil {
		c.kill()
		c.cmd.Wait()
	}
	fileutil.UmountAll(c.dir)
	os.RemoveAll(c.dir)
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

func (c *command) closeWithoutRemove() {
	if c.cmd != nil {
		c.kill()
		c.cmd.Wait()
	}
	if c.inrp != nil {
		c.inrp.Close()
	}
	if c.outwp != nil {
		c.outwp.Close()
	}
}

// Wait for executor to start serving (sandbox setup can take significant time).
func (c *command) waitServing() error {
	read := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := c.inrp.Read(buf[:])
		read <- err
	}()
	timeout := time.NewTimer(time.Minute)
	select {
	case err := <-read:
		timeout.Stop()
		if err != nil {
			c.kill()
			output := <-c.readDone
			err = fmt.Errorf("executor is not serving: %v\n%s", err, output)
			c.cmd.Wait()
			if c.cmd.ProcessState != nil {
				sys := c.cmd.ProcessState.Sys()
				if ws, ok := sys.(syscall.WaitStatus); ok {
					// Magic values returned by executor.
					if ws.ExitStatus() == statusFail {
						err = ExecutorFailure(fmt.Sprintf("executor is not serving:\n%s", output))
					}
				}
			}
		}
		return err
	case <-timeout.C:
		return fmt.Errorf("executor is not serving")
	}
}

func (c *command) kill() {
	syscall.Kill(c.cmd.Process.Pid, syscall.SIGKILL)
}

func (c *command) exec(cover, dedup, needFsState bool) (output []byte, failed, hanged, restart bool, err0 error) {
	var flags [1]byte
	if cover {
		flags[0] |= 1 << 0
		if dedup {
			flags[0] |= 1 << 1
		}
	}
	if needFsState {
		flags[0] |= 1 << 2
	}
	if _, err := c.outwp.Write(flags[:]); err != nil {
		output = <-c.readDone
		err0 = fmt.Errorf("failed to write control pipe: %v", err)
		return
	}
	done := make(chan bool)
	hang := make(chan bool)
	go func() {
		t := time.NewTimer(c.timeout)
		select {
		case <-t.C:
			c.kill()
			hang <- true
		case <-done:
			t.Stop()
			hang <- false
		}
	}()
	readN, readErr := c.inrp.Read(flags[:])
	close(done)
	status := 0
	if readErr == nil {
		if readN != len(flags) {
			panic(fmt.Sprintf("executor %v: read only %v bytes", c.pid, readN))
		}
		status = int(flags[0])
		if status == 0 {
			<-hang
			return
		}
		// Executor writes magic values into the pipe before exiting,
		// so proceed with killing and joining it.
		status = int(flags[0])
	}
	err0 = fmt.Errorf("executor did not answer")
	c.kill()
	output = <-c.readDone
	if err := c.cmd.Wait(); <-hang && err != nil {
		hanged = true
		output = append(output, []byte(err.Error())...)
		output = append(output, '\n')
	}
	switch status {
	case statusFail, statusError, statusRetry:
	default:
		if c.cmd.ProcessState != nil {
			sys := c.cmd.ProcessState.Sys()
			if ws, ok := sys.(syscall.WaitStatus); ok {
				status = ws.ExitStatus()
			}
		}
	}
	// Handle magic values returned by executor.
	switch status {
	case statusFail:
		err0 = ExecutorFailure(fmt.Sprintf("executor failed: %s", output))
	case statusError:
		failed = true
	case statusRetry:
		// This is a temporal error (ENOMEM) or an unfortunate
		// program that messes with testing setup (e.g. kills executor
		// loop process). Pretend that nothing happened.
		// It's better than a false crash report.
		err0 = nil
		hanged = false
		restart = true
	}
	return
}
