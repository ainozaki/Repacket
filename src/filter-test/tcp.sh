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
	ip netns exec outside hping3 172.16.10.1 --baseport 65535 --keep -c 5 -i u100
}

tcp_dst(){
	# hping3 sends TCP packets in default.
	# destination port = 0
	ip netns exec outside hping3 172.16.10.1 --destport 0 -c 1 -i u100

	# dst = 22
	ip netns exec outside hping3 172.16.10.1 --destport 22 -c 2 -i u100

	# dst = 80
	ip netns exec outside hping3 172.16.10.1 --destport 80 -c 3 -i u100

	# dst = 179
	ip netns exec outside hping3 172.16.10.1 --destport 179 -c 4 -i u100

	# dst = 6555
	ip netns exec outside hping3 172.16.10.1 --destport 65535 -c 5 -i u100
}
case $1 in
	"tcp_src") tcp_src;;
	"tcp_dst") tcp_dst;;
	*) echo "[ERROR] invalid argument for tcp.sh.";;
esac
