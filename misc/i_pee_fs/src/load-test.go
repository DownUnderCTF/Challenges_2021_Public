package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

func readLoop(conn *net.UDPConn) {
	for {

		buf := make([]byte, 32)
		_, rAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("error reading packet")
		}
		fmt.Println(string(buf), rAddr)
	}
}

func writeLoop(conn *net.UDPConn, ip net.IP) {
	var counter uint32 = 0
	mutIp := make([]byte, 16)
	copy(mutIp, ip)

	counterBytes := make([]byte, 16)
	binary.BigEndian.PutUint32(counterBytes, counter)

	for {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		copy(mutIp[12:], counterBytes)
		addr := net.UDPAddr{
			IP:   mutIp,
			Port: 1337,
		}

		_, err := conn.WriteTo([]byte(""), &addr)
		if err != nil {
			fmt.Println("error writing packet")
			panic(err)
		}
		counter += 1
	}
}

func main() {
	ip := net.ParseIP("2600:1900:4120:5fb8::")
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{})
	if err != nil {
		fmt.Println("failed to create udp connection", err)
	}

	go writeLoop(conn, ip)
	go readLoop(conn)
	select {}
}
