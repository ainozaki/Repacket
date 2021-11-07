#!/usr/bin/env bash
set -euo pipefail

ip netns add router

ip link add name veth1 type veth peer name router-veth1
ip link set router-veth1 netns router

ip addr add 172.16.10.1/24 dev veth1
ip link set veth1 up

ip netns exec router ip addr add 172.16.10.2/24 dev router-veth1
ip netns exec router ip link set router-veth1 up
ip netns exec router ip link set lo up

echo "Setup Completed."
ip netns exec router ping 172.16.10.1
