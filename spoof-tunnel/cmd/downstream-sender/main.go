package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

func main() {
	var (
		sourceIP   string
		destIP     string
		destPort   int
		listenPort int
		bufferSize int
	)

	flag.StringVar(&sourceIP, "source-ip", "", "spoofed source IPv4 address")
	flag.StringVar(&destIP, "dest-ip", "", "destination IPv4 address")
	flag.IntVar(&destPort, "dest-port", 10808, "destination UDP port")
	flag.IntVar(&listenPort, "listen-port", 10808, "local source UDP port used in forged packets")
	flag.IntVar(&bufferSize, "buffer-size", 1<<20, "socket buffer size")
	flag.Parse()

	if sourceIP == "" || destIP == "" {
		fmt.Fprintln(os.Stderr, "source-ip and dest-ip are required")
		os.Exit(2)
	}
	if destPort < 1 || destPort > 65535 || listenPort < 1 || listenPort > 65535 {
		fmt.Fprintln(os.Stderr, "dest-port/listen-port must be in range 1-65535")
		os.Exit(2)
	}

	src := net.ParseIP(sourceIP)
	dst := net.ParseIP(destIP)
	if src == nil || src.To4() == nil || dst == nil || dst.To4() == nil {
		fmt.Fprintln(os.Stderr, "only IPv4 addresses are supported")
		os.Exit(2)
	}

	cfg := &transport.Config{
		SourceIP:   src,
		ListenPort: uint16(listenPort),
		BufferSize: bufferSize,
		MTU:        1500,
	}

	tx, err := transport.NewUDPTransport(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize UDP transport: %v\n", err)
		os.Exit(1)
	}
	defer tx.Close()

	log.Printf("downstream sender ready source=%s dest=%s:%d", sourceIP, destIP, destPort)

	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			fmt.Fprintf(os.Stderr, "stdin read frame length failed: %v\n", err)
			os.Exit(1)
		}

		payloadLen := binary.BigEndian.Uint32(lenBuf[:])
		if payloadLen == 0 {
			continue
		}
		if payloadLen > (1 << 20) {
			fmt.Fprintf(os.Stderr, "frame too large: %d\n", payloadLen)
			os.Exit(1)
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			fmt.Fprintf(os.Stderr, "stdin read payload failed: %v\n", err)
			os.Exit(1)
		}

		if err := tx.Send(payload, dst, uint16(destPort)); err != nil {
			fmt.Fprintf(os.Stderr, "send failed: %v\n", err)
			os.Exit(1)
		}
	}
}
