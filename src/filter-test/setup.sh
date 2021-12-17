#!/usr/bin/env bash
set -euo pipefail

setup_netns(){
	ip -all netns delete
	ip netns add outside

	ip link add name veth1 type veth peer name outside-veth1
	ip link set outside-veth1 netns outside

	ip addr add 172.16.10.1/24 dev veth1
	ip link set veth1 up

	ip netns exec outside ip addr add 172.16.10.2/24 dev outside-veth1
	ip netns exec outside ip link set outside-veth1 up
	ip netns exec outside ip link set lo up

	echo "Setup Completed."
	ip netns exec outside ping 172.16.10.1 -c 3
	echo "Connected."
}

setup_netns
