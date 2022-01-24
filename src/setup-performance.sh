#!/usr/bin/env bash
set -euo pipefail

RX="enp4s0f0np0"
TX="enp3s0"

setup(){
	ip -all netns del
	ip netns add rx

	ip link set ${RX} netns rx

	ip netns exec rx ip link set ${RX} up
	ip netns exec rx ip addr add 192.0.2.2/24 dev ${RX}

	ip link set ${TX} up
	ip addr add 192.0.2.1/24 dev ${TX}

	ping 192.0.2.2 -c 5
}

setup
