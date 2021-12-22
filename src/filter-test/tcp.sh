#!/usr/bin/env bash
tcp_src(){
	# hping3 sends TCP packets in default.
	# source port = 0
	ip netns exec outside hping3 172.16.10.1 --baseport 0 --keep -c 1 -i u100

	# src = 22
	ip netns exec outside hping3 172.16.10.1 --baseport 22 --keep -c 2 -i u100

	# src = 80
	ip netns exec outside hping3 172.16.10.1 --baseport 80 --keep -c 3 -i u100

	# src = 179
	ip netns exec outside hping3 172.16.10.1 --baseport 179 --keep -c 4 -i u100

	# src = 6555
	# TODO: change to 65535
	ip netns exec outside hping3 172.16.10.1 --baseport 6555 --keep -c 5 -i u100
}

case $1 in
	"tcp_src") tcp_src;;
	*) echo "[ERROR] invalid argument for tcp.sh.";;
esac
