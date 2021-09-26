// probably gonna get banned for players ddosing us before code bottlenecks
// fully redundant concurrency let's gooooooo
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

const FILENAME = "data"
const MASK = ^(uint32(0))
const PER_MINUTE = 512
const LOG_INTERVAL = 32 * 1024
const IPV6_FREEBIND = 78

var ALL = 0

type connectionInfo struct {
	remoteAddr net.UDPAddr
	localAddr  syscall.Inet6Pktinfo
	remote     uint32
	local      uint32
}

func parseLocalAddress(ip net.IP) uint32 {
	length := len(ip)
	return binary.BigEndian.Uint32(ip[length-4:])
}

// rate limit using slice from 24 to 56 bits
func parseRemoteAddress(ip net.IP) uint32 {
	if len(ip) == 4 {
		return binary.BigEndian.Uint32(ip)
	}
	return binary.BigEndian.Uint32(ip[3:7])
}

func checkLimit(limiter map[uint32]uint32, addr uint32) bool {
	now := time.Now().Unix()
	minutes := uint32(now/60) & 65535
	val := limiter[addr]
	cvalue := val & 65535
	cminutes := val >> 16
	if minutes != cminutes {
		limiter[addr] = (minutes << 16) + 1
		return true
	} else if cvalue >= PER_MINUTE {
		return false
	}

	limiter[addr] = (minutes << 16) + ((cvalue + 1) & 65535)
	return true
}

func setupListeners(port string, data []uint32) {
	// Setup UDP listener
	pConn, err := net.ListenPacket("udp6", port)
	if err != nil {
		panic(err)
	}

	sConn := pConn.(*net.UDPConn)

	file, err := sConn.File()
	if err != nil {
		panic(err)
	}

	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
	if err != nil {
		panic(err)
	}
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IPV6, IPV6_FREEBIND, 1)
	if err != nil {
		panic(err)
	}

	defer sConn.Close()

	// Setup channels
	numCPU := runtime.NumCPU()
	queues := make([]chan connectionInfo, numCPU)
	for i := 0; i < numCPU; i++ {
		queues[i] = make(chan connectionInfo)
		go processor(i, sConn, queues[i], data)
	}

	// Setup routers
	for i := 0; i < numCPU; i++ {
		go router(i, sConn, queues, len(queues))
	}

	// Wait forever
	select {}
}

func generateIPv6OOB(localAddr syscall.Inet6Pktinfo) []byte {
	buf := bytes.Buffer{}

	msg := syscall.Cmsghdr{}
	msg.Level = syscall.IPPROTO_IPV6
	msg.Type = syscall.IPV6_PKTINFO

	// clearly a hack, idk why it is 16
	msg.Len = uint64(binary.Size(localAddr) + 16)

	binary.Write(&buf, binary.LittleEndian, msg)
	binary.Write(&buf, binary.LittleEndian, localAddr)

	return buf.Bytes()
}

func processor(procIndex int, conn *net.UDPConn, queue chan connectionInfo, data []uint32) {
	fmt.Println("starting processor routine", procIndex)
	counter := 0
	limiter := make(map[uint32]uint32)
	dataLength := len(data)

	for info := range queue {
		// Construct OOB
		oob := generateIPv6OOB(info.localAddr)
		if checkLimit(limiter, info.remote) {
			counter += 1
			if counter%LOG_INTERVAL == 0 {
				fmt.Println(time.Now(), procIndex, counter)
			}
			conn.WriteMsgUDP([]byte(fmt.Sprintf("%d\n", data[info.local%uint32(dataLength)])), oob, &info.remoteAddr)
		} else {
			conn.WriteMsgUDP([]byte("-1"), oob, &info.remoteAddr)
		}
	}
}

func router(procIndex int, conn *net.UDPConn, queues []chan connectionInfo, qCount int) {
	fmt.Println("starting router routine", procIndex)
	for {
		data := make([]byte, 1024)
		oob := make([]byte, 2048)

		_, _, _, rAddr, _ := conn.ReadMsgUDP(data, oob)
		oob_buffer := bytes.NewBuffer(oob)
		msg := syscall.Cmsghdr{}
		binary.Read(oob_buffer, binary.LittleEndian, &msg)
		if msg.Level == syscall.IPPROTO_IPV6 && msg.Type == syscall.IPV6_PKTINFO {
			local := syscall.Inet6Pktinfo{}
			binary.Read(oob_buffer, binary.LittleEndian, &local)
			h := fnv.New32a()
			h.Write(rAddr.IP[3:7])
			queues[h.Sum32()%uint32(qCount)] <- connectionInfo{
				remoteAddr: *rAddr,
				localAddr:  local,
				remote:     parseRemoteAddress(rAddr.IP),
				local:      parseLocalAddress(local.Addr[:]),
			}
		}

	}
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		return
	}

	data, err := ioutil.ReadFile(FILENAME)
	if err != nil {
		panic("cannot read data file")
	}

	total := len(data) / 4
	numbers := make([]uint32, total)
	for i := 0; i < total; i++ {
		numbers[i] = binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
	}

	setupListeners(arguments[1], numbers)
}
