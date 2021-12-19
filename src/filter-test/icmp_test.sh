#!/usr/bin/env bash
icmp_type(){
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

icmp_code(){
	# icmp type is destination unreachable.
	# icmp code 0 (Net Unreachable)
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 --icmpcode 0 -c 1 -i u100

	# icmp code 1 (Host Unreachable)
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 --icmpcode 1 -c 2 -i u100

	# icmp code 3 (Port Unreachable)
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 --icmpcode 3 -c 3 -i u100

	# icmp code 6 (Desatination Network Unknown)
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 --icmpcode 6 -c 4 -i u100

	# icmp code 15 (Precedence cutoff in effect)
	ip netns exec outside hping3 172.16.10.1 --icmp --icmptype 3 --icmpcode 15 -c 5 -i u100
}

case $1 in
	"icmp_type") icmp_type;;
	"icmp_code") icmp_code;;
	*) echo "invalid argument";;
esac
