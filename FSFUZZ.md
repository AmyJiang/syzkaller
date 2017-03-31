Differential Testing of Linux File Systems
======================================
> extending Syzkaller for fuzzing multiple file systems

## Running extended Syzkaller

### Setup and build Syzkaller
- Follow original [Syzkaller](https://github.com/google/syzkaller) README carefully
- Enable options related to the file systems under test when configuring the Linux kernel


### Create a disk image
[`partition_image.sh`](tools/parition_image.sh) could be used to create a
suitable Linux image of three partitions: one boot parition in ext4, and two
paritions formated in two different file systems (as ext4 and xfs in the script).
The test partitions are mounted at start time in default as /testfs1 and /testfs2.

### Configure

`fsfuzz.cfg.test`(fsfuzz.cfg.test) is a sample configuration file:
- "cmdline": "root=/dev/sda3"
    sda3 is the default boot partition in an image created by the `partition_image.sh` script
- "filesystems": ["/testfs1", "/testfs2"]


## Run
Start the `syz-manager` process as:
```
        bin/syz-manager -config fsfuzz.cfg.test #-debug
```
The `syz-manager` process will wind up qemu virtual machines and start fuzzing in them.
It also reports some statistics on the HTTP address.


## Analyzing results
When the modified `syzkaller` finds a diff-inducing program (i.e. a program that
has different behavior in the test file systems), it saves the program in
`workdir/diff.db`

### Unpack `diff.db`
To unpack the directory, use
```
./bin/syz-db unpack diff.db diff.dir`
```

In the unpacked diff.dir, for each diff-inducing program, there is also the program it mutates froms: `xxxx_BeforeMutationWas_yyyy`. `xxxx` is the SHA1 hash of the
diff-inducing program, and `yyyy` is the hash of the program before mutation. Comparing the two program, one could localize the changes in syscalls that lead to the discrepency.

### Examine one diff-inducing program
To produce an equivalent C program, use
```
`./bin/syz-prog2c -prog <diff.dir/xxxx>`
```

### Triage all diffs
The tool [`syz-triagediff`](tools/syz-triagediff/triagediff.go) could be used to

Sample command (recommended):
```
    ./bin/syz-triagediff -executor=./syz-executor  -collide=0 -threaded=0 -cover=0 \
    -procs=2  -testdirs="/testfs1:/testfs2" -verbose=0 \
    diff.dir
```


