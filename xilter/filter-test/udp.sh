#!/usr/bin/env bash
udp_src(){
	# source port = 0
	ip netns exec outside hping3 172.16.10.1 --udp --baseport 0 --keep -c 1 -i u10

	# src = 22
	ip netns exec outside hping3 172.16.10.1 --udp --baseport 22 --keep -c 2 -i u10

	# src = 80
	ip netns exec outside hping3 172.16.10.1 --udp --baseport 80 --keep -c 3 -i u10

	# src = 179
	ip netns exec outside hping3 172.16.10.1 --udp --baseport 179 --keep -c 4 -i u10

	# src = 6555
	ip netns exec outside hping3 172.16.10.1 --udp --baseport 65535 --keep -c 5 -i u10
}

udp_dst(){
	# destination port = 0
	ip netns exec outside hping3 172.16.10.1 --udp --destport 0 -c 1 -i u10

	# dst = 22
	ip netns exec outside hping3 172.16.10.1 --udp --destport 22 -c 2 -i u10

	# dst = 80
	ip netns exec outside hping3 172.16.10.1 --udp --destport 80 -c 3 -i u10

	# dst = 179
	ip netns exec outside hping3 172.16.10.1 --udp --destport 179 -c 4 -i u10

	# dst = 6555
	ip netns exec outside hping3 172.16.10.1 --udp --destport 65535 -c 5 -i u10
}

case $1 in
	"udp_src") udp_src;;
	"udp_dst") udp_dst;;
	*) echo "[ERROR] invalid argument for udp.sh.";;
esac
