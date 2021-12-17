#!/usr/bin/env bash
set -euo pipefail

icmp_tests(){
	ip netns exec outside hping3 172.16.10.1 --icmp -c 10 -i u100
	echo "finish hping3"
}

icmp_tests
