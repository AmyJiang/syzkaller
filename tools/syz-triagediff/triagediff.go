// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// triagediff groups a set of diff-inducing programs by their syscalls and
// prints out debug information about execution and file system status
//

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor  = flag.String("executor", "./syz-executor", "path to executor binary")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 1, "number of parallel processes to execute programs")
	flagTestdirs  = flag.String("testdirs", "", "colon-separated list of test directories")
)

func static_analyze(diffdir string) {
	lastcall := make(map[string]int)
	calls := make(map[string]int)
	sig := make(map[string]int)

	files, err := ioutil.ReadDir(diffdir)
	if err != nil {
		Fatalf("failed to read directory: %v", diffdir)
	}
	failed := 0
	for _, fn := range files {
		data, err := ioutil.ReadFile(filepath.Join(diffdir, fn.Name()))
		if err != nil {
			fmt.Printf("failed to read prog: %v\n", err)
			return
		}
		p, err := prog.Deserialize(data)
		if err != nil {
			failed++
			continue
		}
		sig[p.String()]++
		lastcall[p.Calls[len(p.Calls)-1].Meta.Name]++
		for _, c := range p.Calls {
			calls[c.Meta.Name]++
		}

	}
	fmt.Printf("Triage %v programs (%v failed)", len(files), failed)
	fmt.Printf("\nCount call chain:\n")
	for k, v := range sig {
		fmt.Printf("  %v: %v\n", k, v)
	}

	fmt.Printf("\nCount last call:\n")
	for k, v := range lastcall {
		fmt.Printf("  %v: %v\n", k, v)
	}

	fmt.Printf("\n Count all calls:\n")
	for k, v := range calls {
		fmt.Printf("  %v: %v\n", k, v)
	}

}

func has_diff(statuses [][]uint32) bool {
	for i := 1; i < len(statuses); i += 1 {
		if len(statuses[i]) != len(statuses[i-1]) {
			return true
		}
		for j, v1 := range statuses[i-1] {
			if statuses[i][j] != v1 {
				return true
			}
		}
	}
	return false
}

func diff_analyze(diffdir string) {
	if *flagTestdirs == "" {
		Fatalf("failed to get test directories from flag")
	}
	testdirs := strings.Split(*flagTestdirs, ":")
	fmt.Printf("testdirs: %v\n", testdirs)

	flags, timeout, err := ipc.DefaultFlags()
	if err != nil {
		Fatalf("%v", err)
	}
	needCover := flags&ipc.FlagSignal != 0
	dedupCover := true
	if *flagCoverFile != "" {
		flags |= ipc.FlagSignal
		needCover = true
		dedupCover = false
	}

	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	var logMu sync.Mutex
	// gate := ipc.NewGate(2**flagProcs, nil)
	var shutdown uint32
	candidates := make(chan struct {
		prog *prog.Prog
		name string
	}, 100)

	files, err := ioutil.ReadDir(diffdir)
	if err != nil {
		Fatalf("failed to read directory: %v", diffdir)
	}
	go func() {
		defer close(candidates)
		failed := 0
		for _, fn := range files {
			if atomic.LoadUint32(&shutdown) != 0 {
				return
			}
			data, err := ioutil.ReadFile(filepath.Join(diffdir, fn.Name()))
			if err != nil {
				fmt.Printf("failed to read prog: %v\n", err)
				return
			}
			p, err := prog.Deserialize(data)
			if err != nil {
				failed++
				continue
			}
			for i := 0; i < *flagRepeat; i++ {
				candidates <- struct {
					prog *prog.Prog
					name string
				}{p, fn.Name()}
			}
		}
	}()

	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			var diffs []string
			defer wg.Done()
			env, err := ipc.MakeEnv(*flagExecutor, timeout, flags, pid)
			if err != nil {
				Fatalf("failed to create ipc env: %v", err)
			}
			defer env.Close()
			for c := range candidates {
				// Limit concurrency window.
				// ticket := gate.Enter()
				// defer gate.Leave(ticket)

				candidate := c.prog
				name := c.name
				logMu.Lock()
				Logf(0, "executing program %v: %s", pid, name)
				logMu.Unlock()

				statuses := make([][]uint32, len(testdirs))
				for i, dir := range testdirs {
					if atomic.LoadUint32(&shutdown) != 0 {
						return
					}
					output, info, failed, hanged, err, status := env.Exec(candidate, needCover, dedupCover, true, dir)
					statuses[i] = append(statuses[i], status...)
					if failed {
						fmt.Printf("BUG: executor-detected bug:\n%s", output)
					}
					if flags&ipc.FlagDebug != 0 || err != nil {
						fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
					}
					if *flagCoverFile != "" {
						// Coverage is dumped in sanitizer format.
						// github.com/google/sanitizers/tools/sancov command can be used to dump PCs,
						// then they can be piped via addr2line to symbolize.
						for i, inf := range info {
							fmt.Printf("call #%v: signal %v, coverage %v\n", i, len(inf.Signal), len(inf.Cover))
							if len(inf.Cover) == 0 {
								continue
							}
							buf := new(bytes.Buffer)
							binary.Write(buf, binary.LittleEndian, uint64(0xC0BFFFFFFFFFFF64))
							for _, pc := range inf.Cover {
								binary.Write(buf, binary.LittleEndian, cover.RestorePC(pc, 0xffffffff))
							}
							err := ioutil.WriteFile(fmt.Sprintf("%v.%v", *flagCoverFile, i), buf.Bytes(), 0660)
							if err != nil {
								Fatalf("failed to write coverage file: %v", err)
							}
						}
					}
				}
				if has_diff(statuses) {
					diffs = append(diffs, name)
				}
			}

			for _, n := range diffs {
				fmt.Printf("%v detected diff: %v\n", pid, n)
			}
		}()
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		Logf(0, "shutting down...")
		atomic.StoreUint32(&shutdown, 1)
		<-c
		Fatalf("terminating")
	}()

	wg.Wait()
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: triagediff [flags] diff-dir \n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	diffdir := flag.Args()[0]
	// static_analyze(diffdir)
	diff_analyze(diffdir)
}
