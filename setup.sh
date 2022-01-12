#!/bin/bash
set -xeuo pipefail
LINUX_VERSION=5.4.49

ROOT_DIR=$(pwd)

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

get-software-ubuntu(){
	sudo apt update
	sudo apt install -y clang clang-format cmake llvm libelf-dev libpcap-dev gcc-multilib build-essential
	sudo apt install -y linux-tools-$(uname -r) linux-headers-$(uname -r)
}

get-yaml-cpp(){
	cd ~
	git clone https://github.com/jbeder/yaml-cpp.git
	cd ~/yaml-cpp
	mkdir build
	cd ~/yaml-cpp/build
	cmake ..
	make
	sudo make install
	echo -e "${COLOR_GREEN}[ INFO ] yaml-cpp installed ${COLOR_OFF}"
}

get-cmdline(){
	cd ~
	git clone https://github.com/tanakh/cmdline.git
	sudo mv ~/cmdline/cmdline.h /usr/local/include
	echo -e "${COLOR_GREEN}[ INFO ] cmdline installed ${COLOR_OFF}"
}

get-libbpf() {
    DEPS=${ROOT_DIR}/deps
    mkdir -p ${DEPS}
    if [ -f ${DEPS}/libbpf_installed ]; then
        return
    fi
    LIBBPF=${DEPS}/libbpf
    INSTALL=${DEPS}
    mkdir -p ${DEPS}/lib
    mkdir -p ${DEPS}/include
    rm -rf ${LIBBPF}
    pushd .
    cd ${DEPS}
		git clone https://github.com/libbpf/libbpf || true
    cd "${LIBBPF}"
    git checkout b91f53e
    cd ${LIBBPF}/src
    make
    DESTDIR=$INSTALL make install
    cd $LIBBPF
    cp -r include/uapi $INSTALL/usr/include/bpf/
    cd $INSTALL
    mv $INSTALL/usr/include/bpf $INSTALL/include/
    cp -r $INSTALL/usr/lib64/* $INSTALL/lib/
    echo -e "${COLOR_GREEN}libbpf is installed ${COLOR_OFF}"
    popd
    touch ${DEPS}/libbpf_installed
}

#get-software-ubuntu
get-libbpf
#get-yaml-cpp
#get-cmdline
