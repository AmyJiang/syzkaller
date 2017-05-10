#!/bin/bash

sudo apt-get -y update
sudo apt-get install build-essential software-properties-common bc libssl-dev -y 

# Get GCC
sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y 
sudo apt-get update
sudo apt-get install gcc-6 g++-6 -y
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 60 --slave /usr/bin/g++ g++ /usr/bin/g++-6    

# QEMU
sudo apt-get install kvm qemu-kvm -y


# Get GO
wget https://storage.googleapis.com/golang/go1.8.linux-amd64.tar.gz
tar -xvf go1.8.linux-amd64.tar.gz go

echo "export GOROOT=$HOME/go" >> ~/.bashrc
echo "export PATH=$HOME/go/bin:$PATH" >> ~/.bashrc
echo "export GOPATH=$HOME/fsfuzz" >> ~/.bashrc
source ~/.bashrc

# Get FSFUZZ (modified syzkaller)
pushd $GOPATH 
  mkdir -p src bin pkg
  mkdir -p src/github.com/google
popd
pushd $GOPATH/src/github.com/google
  rm -rf syzkaller
  git clone -b fs-diff https://github.com/AmyJiang/syzkaller.git syzkaller
  pushd syzkaller
	  go get -d ./...
  popd
popd
echo $PWD

# Get linux kernel for fuzzing
git clone https://github.com/torvalds/linux.git linux-kernel 
pushd linux-kernel
  make clean
  make defconfig
  make kvmconfig
  cp $GOPATH/src/github.com/google/syzkaller/.config .config
  yes "" | make oldconfig
  make -j4
popd

# install debootstrap
sudo apt-get install debootstrap

# build test disk image
$GOPATH/src/github.com/google/syzkaller/tools/create-image.sh
$GOPATH/src/github.com/google/syzkaller/tools/partition-image.sh

# build Syzkaller
pushd $GOPATH/src/github.com/google/syzkaller
  make 
popd
