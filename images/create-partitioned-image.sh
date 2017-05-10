#!/bin/bash
set -eux

# Build a disk image
rm -rf wheezy.img
dd if=/dev/zero of=wheezy.img bs=5M seek=1023 count=1

# Old: 2 partitions (ext4 as boot sda1, xfs as sda2)
# echo -e "o\nn\np\n1\n\n+500M\nn\np\n2\n\n\nw" | fdisk wheezy.img

# New: 3 partitions (ext4 for test, xfs for test, ext4 for boot)
echo -e "o\nn\np\n1\n\n+1G\nn\np\n2\n\n+1G\nn\np\n3\n\n\nw\n" | fdisk wheezy.img

# The partition table should looks like:
# Device      Boot   Start      End Sectors Size Id Type
# wheezy.img1         2048  2099199 2097152   1G 83 Linux
# wheezy.img2      2099200  4196351 2097152   1G 83 Linux
# wheezy.img3 *    4196352 10485759 6289408   3G 83 Linux

# Setup partition
sudo losetup -D
sudo losetup -o $((2048*512)) --sizelimit $((2097152*512)) /dev/loop1 wheezy.img
sudo mkfs.ext4 -F /dev/loop1

sudo losetup -o $((2099200*512)) --sizelimit $((2097152*512)) /dev/loop2 wheezy.img
sudo mkfs.xfs -f /dev/loop2

sudo losetup -o $((4196352*512)) --sizelimit $((6289408*512)) /dev/loop3 wheezy.img
sudo mkfs.ext4 -F /dev/loop3



sudo mkdir -p /mnt/wheezy
sudo mount -t ext4 /dev/loop3 /mnt/wheezy

sudo mkdir -p wheezy/testfs1 wheezy/testfs2
sudo cp -a wheezy/. /mnt/wheezy/.

sudo echo '/dev/sda1 /testfs1 ext4 defaults 0 0' | sudo tee -a /mnt/wheezy/etc/fstab
sudo echo '/dev/sda2 /testfs2 xfs defaults 0 0' | sudo tee -a /mnt/wheezy/etc/fstab

sudo umount /mnt/wheezy
sudo losetup -D



