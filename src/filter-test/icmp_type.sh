#!/usr/bin/env bash
icmp_tests(){
	# icmp echo reply
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 0 -c 1 -i u100

	# icmp destination unreachable
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 -c 2 -i u100

	# icmp redirect
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 5 -c 3 -i u100

	# icmp echo request
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 8 -c 4 -i u100

	# icmp time exceeded
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 11 -c 5 -i u100
}

icmp_tests
