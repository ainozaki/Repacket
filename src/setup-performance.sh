#!/usr/bin/env bash
set -euo pipefail

TX="enp4s0f1np1"
RX="enp3s0"

setup(){
	ip -all netns del
	ip netns add tx
	ip netns add rx

	ip link set ${TX} netns tx
	ip link set ${RX} netns rx

	ip netns exec tx ip link set ${TX} up
	ip netns exec tx ip addr add 172.16.100.10/24 dev ${TX}

	ip netns exec rx ip link set ${RX} up
	ip netns exec rx ip addr add 172.16.100.20/24 dev ${RX}

	ip netns exec tx ping 172.16.100.20 -c 5
}

setup
