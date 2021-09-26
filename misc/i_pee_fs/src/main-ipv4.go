// probably gonna get banned for players ddosing us before code bottlenecks
// fully redundant concurrency let's gooooooo
package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const FILENAME = "data"
const PER_MINUTE = 512

var ALL = 0

type logWriter struct {
}

type connectionInfo struct {
	offset int
	remote net.UDPAddr
}

func checkLimit(limiter map[uint32]uint32, addr net.IP) bool {
	ip := binary.BigEndian.Uint32(addr[len(addr)-4:])
	now := time.Now().Unix()
	minutes := uint32(now/60) & 65535
	val := limiter[ip]
	cvalue := val & 65535
	cminutes := val >> 16
	if minutes != cminutes {
		limiter[ip] = (minutes << 16) + 1
		return true
	} else if cvalue >= PER_MINUTE {
		if cvalue == PER_MINUTE {
			log.Printf("rate limit reached for %s", addr)
		}
		if cvalue < 65535 {
			limiter[ip] = (minutes << 16) + ((cvalue + 1) & 65535)
		}
		return false
	}

	limiter[ip] = (minutes << 16) + ((cvalue + 1) & 65535)
	return true
}

func setupListeners(port string, data []uint32) {
	// Setup UDP listener
	pConn, err := net.ListenPacket("udp", port)
	if err != nil {
		panic(err)
	}

	sConn := pConn.(*net.UDPConn)
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

func processor(procIndex int, conn *net.UDPConn, queue chan connectionInfo, data []uint32) {
	log.Println("starting processor routine", procIndex)
	counter := 0
	limiter := make(map[uint32]uint32)
	dataLength := len(data)

	for info := range queue {
		// Construct OOB
		if checkLimit(limiter, info.remote.IP) {
			counter += 1
			conn.WriteTo([]byte(fmt.Sprintf("%d\n", uint64(info.offset<<32)+uint64(data[info.offset%dataLength]))), &info.remote)
		} else {
			conn.WriteTo([]byte("-1"), &info.remote)
		}
	}
}

func router(procIndex int, conn *net.UDPConn, queues []chan connectionInfo, qCount int) {
	log.Println("starting router routine", procIndex)
	for {
		data := make([]byte, 12)
		_, addr, err := conn.ReadFrom(data)
		if err != nil {
			// log error
			continue
		}
		uAddr := addr.(*net.UDPAddr)

		off, err := strconv.Atoi(strings.Trim(string(data), "\n\t\x00 "))
		if err != nil || off < 0 {
			conn.WriteTo([]byte("-1"), uAddr)
			continue
		}

		h := fnv.New32a()
		h.Write(uAddr.IP)
		queues[h.Sum32()%uint32(qCount)] <- connectionInfo{
			offset: off,
			remote: *uAddr,
		}

	}
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		log.Println("Please provide a port number!")
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
