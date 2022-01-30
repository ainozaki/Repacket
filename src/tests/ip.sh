#!/usr/bin/env bash
ip_protocol(){
	# raw ip with protocol option set.
	# ICMP
	ip netns exec outside hping3 172.16.10.1 --icmp -c 1 -i u10

	# TCP
	# hping3 sends TCP packet in default.
	ip netns exec outside hping3 172.16.10.1 -c 2 -i u10

	# UDP
	ip netns exec outside hping3 172.16.10.1 --udp -c 3 -i u10
}

ip_saddr(){
	# use fake IP source address.
	ip netns exec outside hping3 172.16.10.1 --spoof 192.0.2.0 -c 1 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 192.0.2.254 -c 2 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 198.51.100.10 -c 3 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 198.51.100.100 -c 4 -i u10

	ip netns exec outside hping3 172.16.10.1 --spoof 203.0.113.1 -c 5 -i u10
}

ip_tos(){
	# Type of Service field is 00000000
	ip netns exec outside hping3 172.16.10.1 --tos 0 -c 1 -i u10

	# 00000010
	ip netns exec outside hping3 172.16.10.1 --tos 2 -c 2 -i u10

	# 00000100
	ip netns exec outside hping3 172.16.10.1 --tos 4 -c 3 -i u10

	# 00001000
	ip netns exec outside hping3 172.16.10.1 --tos 8 -c 4 -i u10

	# 00001010
	ip netns exec outside hping3 172.16.10.1 --tos 10 -c 5 -i u10
}

ip_ttl(){
	# Time To Live is 2.
	ip netns exec outside hping3 172.16.10.1 --ttl 2 -c 1 -i u10

	# TTL 20.
	ip netns exec outside hping3 172.16.10.1 --ttl 20 -c 2 -i u10

	# TTL 40.
	ip netns exec outside hping3 172.16.10.1 --ttl 40 -c 3 -i u10

	# TTL 80.
	ip netns exec outside hping3 172.16.10.1 --ttl 80 -c 4 -i u10

	# TTL 240.
	ip netns exec outside hping3 172.16.10.1 --ttl 240 -c 5 -i u10
}

ip_tot_len(){
	# Use icmp echo request. Header size of icmp echo request is 28.
	# Total Length = 48.
	ip netns exec outside hping3 172.16.10.1 --icmp --data 20 -c 1 -i u10

	# tot_len = 68.
	ip netns exec outside hping3 172.16.10.1 --icmp --data 40 -c 2 -i u10

	# tot_len = 228.
	ip netns exec outside hping3 172.16.10.1 --icmp --data 200 -c 3 -i u100

	# tot_len = 528.
	ip netns exec outside hping3 172.16.10.1 --icmp --data 500 -c 4 -i u100

	# tot_len = 1028.
	ip netns exec outside hping3 172.16.10.1 --icmp --data 1000 -c 5 -i u100
}

case $1 in
	"ip_protocol") ip_protocol;;
	"ip_saddr") ip_saddr;;
	"ip_tos") ip_tos;;
	"ip_ttl") ip_ttl;;
	"ip_tot_len") ip_tot_len;;
	*) echo "[ERROR] invalid argument";;
esac
