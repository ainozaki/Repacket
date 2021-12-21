#!/usr/bin/env bash
ip_protocol(){
	# raw ip with protocol option set.
	# ICMP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 1 -c 1 -i u10

	# TCP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 6 -c 2 -i u10

	# UDP
	ip netns exec outside hping3 172.16.10.1 --rawip --ipproto 17 -c 3 -i u10
}

ip_saddr(){
	# use fake IP source address.
	ip netns exec outside hping3 172.16.10.1 --spoof 192.0.2.0 -c 1 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 192.0.2.254 -c 2 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 198.51.100.10 -c 3 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 198.51.100.100 -c 4 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 203.0.113.1 -c 5 -i u10
}

case $1 in
	"ip_protocol") ip_protocol;;
	"ip_saddr") ip_saddr;;
	*) echo "invalid argument";;
esac
