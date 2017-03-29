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
    "path/filepath"
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	flagOutput    = flag.String("output", "none", "write programs to none/stdout")
)

func static_analyze(progs map[string]*prog.Prog) {
    lastcall := make(map[string]int)
    calls := make(map[string]int)
    sig := make(map[string]int)

    for _, p := range(progs) {
        sig[p.String()]++
        lc := p.Calls[len(p.Calls)-1].Meta.Name
        lastcall[lc]++
        for _, c := range p.Calls {
            calls[c.Meta.Name]++
        }
	}

    Logf(0, "\nCount call chain:");
    for k, v := range(sig) {
        fmt.Printf("  %v: %v\n", k, v)
    }


    Logf(0, "\nCount last call:");
    for k, v := range(lastcall) {
        fmt.Printf("  %v: %v\n", k, v)
    }

    Logf(0, "\n Count all calls:");
    for k, v := range(calls) {
        fmt.Printf("  %v: %v\n", k, v)
    }
}

// TODO (never tested)
func run_analyze(progs []*prog.Prog) {
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

	flags |= ipc.FlagDebug

	handled := make(map[string]bool)
	for _, prog := range progs {
		for _, call := range prog.Calls {
			handled[call.Meta.CallName] = true
		}
	}
	if handled["syz_emit_ethernet"] {
		flags |= ipc.FlagEnableTun
	}

	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	var posMu, logMu sync.Mutex
	gate := ipc.NewGate(2**flagProcs, nil)
	var pos int
	var lastPrint time.Time
	var shutdown uint32
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			env, err := ipc.MakeEnv(*flagExecutor, timeout, flags, pid)
			if err != nil {
				Fatalf("failed to create ipc env: %v", err)
			}
			defer env.Close()
			fmt.Printf("Pos = %v\n", pos)
			for pos < len(progs) {
				if !func() bool {
					// Limit concurrency window.
					ticket := gate.Enter()
					defer gate.Leave(ticket)

					posMu.Lock()
					idx := pos
					pos++
					if idx%len(progs) == 0 && time.Since(lastPrint) > 5*time.Second {
						Logf(0, "executed programs: %v", idx)
						lastPrint = time.Now()
					}
					posMu.Unlock()
					if *flagRepeat > 0 && idx >= len(progs)**flagRepeat {
						return false
					}
					p := progs[idx%len(progs)]
					switch *flagOutput {
					case "stdout":
						logMu.Lock()
						Logf(0, "executing program %v:\n%s", pid, p)
						logMu.Unlock()
					}
					output, info, failed, hanged, err, _ := env.Exec(p, needCover, dedupCover, false, "./")
					if atomic.LoadUint32(&shutdown) != 0 {
						return false
					}
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
					return true
				}() {
					return
				}
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
    files, err := ioutil.ReadDir(diffdir)
    if err != nil {
        Fatalf("failed to read directory: %v", diffdir)
    }


    failed := 0
    progs := make(map[string]*prog.Prog)
    for _, fn := range files {
		data, err := ioutil.ReadFile(filepath.Join(diffdir, fn.Name()))
		if err != nil {
			Fatalf("failed to read prog: %v", err)
		}
        p, err := prog.Deserialize(data)
        if err != nil {
            failed++;
            continue
        }
        progs[fn.Name()] = p
    }

    Logf(0, "Triaged %v programs", len(progs))
    if len(progs) == 0 {
        return
    }
    static_analyze(progs)
    // run_analyze(progs)
}

