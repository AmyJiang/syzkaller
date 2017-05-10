#!/bin/bash
# Copyright 2016 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# create-testfs-image.sh creates suitable disk images formatted in filesystems under test

set -eux

sudo losetup -D

rm -rf test-*.img

# Build disk images formatted in ext4, xfs and gfs2.
dd if=/dev/zero of=test-ext4.img bs=1M seek=1023 count=1
echo -e "o\nn\np\n\n\n\nw\n" | fdisk test-ext4.img
sudo kpartx -as test-ext4.img
sudo mkfs.ext4 -F /dev/dm-0
sudo kpartx -ds test-ext4.img

dd if=/dev/zero of=test-xfs.img bs=1M seek=1023 count=1
echo -e "o\nn\np\n\n\n\nw\n" | fdisk test-xfs.img
sudo kpartx -as test-xfs.img
sudo mkfs.xfs -f /dev/dm-0
sudo kpartx -ds test-xfs.img


dd if=/dev/zero of=test-gfs2.img bs=1M seek=1023 count=1
echo -e "o\nn\np\n\n\n\nw\n" | fdisk test-gfs2.img
sudo kpartx -as test-gfs2.img
sudo mkfs.gfs2 -p lock_nolock -j 1 /dev/dm-0
sudo kpartx -ds test-gfs2.img

# Mount testfs devices
mkdir -p /mnt/wheezy
sudo losetup /dev/loop1 wheezy.img
sudo mount -t ext4 /dev/loop1 /mnt/wheezy
sudo mkdir -p /mnt/wheezy/testfs1 /mnt/wheezy/testfs2 /mnt/wheezy-testfs3
sudo echo '/dev/sdb1 /testfs1 ext4 defaults 0 0' | sudo tee -a /mnt/wheezy/etc/fstab
sudo echo '/dev/sdc1 /testfs2 xfs defaults 0 0' | sudo tee -a /mnt/wheezy/etc/fstab
sudo echo '/dev/sdd1 /testfs3 gfs2 rw,relatime,localflocks 0 0' | sudo tee -a /mnt/wheezy/etc/fstab
sudo umount /mnt/wheezy
sudo losetup -D
