#!/bin/bash
set -eux

# Build a disk image with 2 partitions
rm -rf wheezy.img
dd if=/dev/zero of=wheezy.img bs=1M seek=1023 count=1
echo -e "o\nn\np\n1\n\n+500M\nn\np\n2\n\n\nw" | fdisk wheezy.img

# Setup partition
sudo losetup -D
sudo losetup -o $((2048*512)) --sizelimit $((1024000*512)) /dev/loop1 wheezy.img
sudo mkfs.ext4 -F /dev/loop1

sudo losetup -o $((1026048*512)) --sizelimit $((1071104*512)) /dev/loop2 wheezy.img
sudo mkfs.xfs -f /dev/loop2

sudo mkdir -p /mnt/wheezy
sudo mount -t ext4 /dev/loop1 /mnt/wheezy
sudo mkdir -p wheezy/testfs
sudo cp -a wheezy/. /mnt/wheezy/.
sudo echo '/dev/sda2 /testfs xfs defaults 0 0' | sudo tee -a /mnt/wheezy/etc/fstab

sudo umount /mnt/wheezy
sudo losetup -D



