Differential Testing of Linux File Systems
======================================
> extending Syzkaller for fuzzing multiple file systems

## Running extended Syzkaller

### Setup and build Syzkaller
- Follow original [Syzkaller](https://github.com/google/syzkaller) README carefully
- Enable options related to the file systems under test when configuring the Linux kernel


### Create a disk image
[`partition-image.sh`](tools/parition-image.sh) could be used to create a
suitable Linux image of three partitions: one boot parition in ext4, and two
partitions formated in two different file systems (as ext4 and xfs in the script).
The test partitions are mounted at start time in default as /testfs1 and /testfs2.

### Configure

[`fsfuzz.cfg.test`](fsfuzz.cfg.test) is a sample configuration file:
- "cmdline": "root=/dev/sda3"
    
    sda3 is the default boot partition in an image created by the `partition-image.sh` script
    
- "filesystems": ["/testfs1", "/testfs2"]


## Run
Start the `syz-manager` process as:
```
$ ./bin/syz-manager -config fsfuzz.cfg.test #-debug
```
The `syz-manager` process will wind up qemu virtual machines and start fuzzing in them.
It also reports some statistics on the HTTP address.


## Analyzing results
When the modified `syzkaller` finds a diff-inducing program (i.e. a program that
causes different statues in the test file systems), it saves the program in
`workdir/diff.db`

### Unpack `diff.db`
To unpack the directory, use
```
./bin/syz-db unpack diff.db diff.dir`
```

In the unpacked diff.dir, each diff-inducing program is named as the SHA1 hash of its content. There is also a program from which each diff-inducing program mutates: `xxxx_BeforeMutationWas_yyyy`. `xxxx` is name/hash of the diff-inducing program, and `yyyy` is the hash of the program before mutation (i.e this file). Comparing the two programs, one could localize the changes in syscalls that lead to the discrepency.

### Examine one diff-inducing program
To produce an equivalent C program, use
```
$ ./bin/syz-prog2c -prog <diff.dir/xxxx>
```

### Triage diff-inducing program
The tool [`syz-triagediff`](tools/syz-triagediff/triagediff.go) could be used to analyze diff-inducing programs and reproduce diffs.

* Copy binaries and the program to test machine
```
$ scp -i ssh/id_rsa -P 10021 -r bin/syz-triagediff bin/syz-executor diff_dir test@machine
```

* Run the program on the test machine:
```
$ ./syz-triagediff -executor ./syz-executor -cover=0 -threaded=0 -collide=0 -procs=2 \
-testdirs="/testfs1:/testfs2" \
diff.dir
```

* Several Useful flags
```
  -cover
    	collect feedback signals (coverage) (default true)
  -debug
    	debug output from executor
  -executor string
    	path to executor binary (default "./syz-executor")
  -procs int
    	number of parallel processes to execute programs (default 1)
  -testdirs string
    	colon-separated list of test directories
```

For fuzzing file systems, we need flags `-threaded=0 -collide=0` to execute test programs as a simple single-threaded sequence of syscalls, and flags `-testdirs` to run the test program under different file systems. Flag `-debug=1` can output the debug messages from executor and the file system status.

