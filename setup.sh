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
    DEPS_DIR="${ROOT_DIR}/deps"
    mkdir -p "${DEPS_DIR}"
    if [ -f "${DEPS_DIR}/libbpf_installed" ]; then
        return
    fi
    LIBBPF_DIR="${DEPS_DIR}/libbpf"
    INSTALL_DIR=${DEPS_DIR}
    mkdir -p "${INSTALL_DIR}/lib"
    mkdir -p "${INSTALL_DIR}/include"
    rm -rf "${LIBBPF_DIR}"
    pushd .
    cd "${DEPS_DIR}"
    echo -e "${COLOR_GREEN}[ INFO ] Cloning libbpf repo ${COLOR_OFF}"
    #git clone --depth 1 https://github.com/libbpf/libbpf || true
    git clone https://github.com/libbpf/libbpf || true
    cd "${LIBBPF_DIR}"
    git checkout b91f53e
    cd "${LIBBPF_DIR}"/src
    make
    #on centos the cp -fpR used was throwing an error, so just use a regular cp -R
    if [ -f /etc/redhat-release ]; then
        sed -i 's/cp -fpR/cp -R/g' Makefile
    fi
    DESTDIR="$INSTALL_DIR" make install
    cd "$LIBBPF_DIR"
    cp -r include/uapi "$INSTALL_DIR"/usr/include/bpf/
    # Move to CMAKE_PREFIX_PATH so that cmake can easily discover them
    cd "$INSTALL_DIR"
    mv "$INSTALL_DIR"/usr/include/bpf "$INSTALL_DIR"/include/
    cp -r "$INSTALL_DIR"/usr/lib64/* "$INSTALL_DIR"/lib/
    echo -e "${COLOR_GREEN}libbpf is installed ${COLOR_OFF}"
    popd
    touch "${DEPS_DIR}/libbpf_installed"
}

get-software-ubuntu
get-libbpf
#get-yaml-cpp
#get-cmdline
