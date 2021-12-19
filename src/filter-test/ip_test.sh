#!/usr/bin/env bash
ip_protocol(){
	# raw ip with protocol option set.
	# ICMP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 1 -c 1 -i u100

	# TCP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 6 -c 2 -i u100

	# UDP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 17 -c 3 -i u100
}

case $1 in
	"ip_protocol") ip_protocol;;
	*) echo "invalid argument";;
esac
