package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

const (
	magic   = "HTUN"
	version = 1

	typeHello = 1
	typeReady = 2
	typeData  = 3
	typePing  = 4
	typePong  = 5
	typeAck   = 6
	typeClose = 7
	typeError = 8

	ackSackWindow = 64
)

type config struct {
	VPSInIP                  string  `json:"vps_in_ip"`
	SpoofIP                  string  `json:"spoof_ip"`
	UDPPort                  int     `json:"udp_port"`
	ControlPort              int     `json:"control_port"`
	ListenHost               string  `json:"listen_host"`
	UDPMTU                   int     `json:"udp_mtu"`
	ResendInterval           float64 `json:"resend_interval"`
	RetransmitScanInterval   float64 `json:"retransmit_scan_interval"`
	MaxResendsPerTick        int     `json:"max_resends_per_tick"`
	ResendBackoffFactor      float64 `json:"resend_backoff_factor"`
	MaxPendingChunks         int     `json:"max_pending_chunks"`
	TargetRecvSize           int     `json:"target_recv_size"`
	SocketBufferBytes        int     `json:"socket_buffer_bytes"`
	UDPPlainFallbackEnabled  bool    `json:"udp_plain_fallback_enabled"`
	SessionCloseGrace        float64 `json:"session_close_grace"`
	KeepaliveInterval        float64 `json:"keepalive_interval"`
	KeepaliveTimeout         float64 `json:"keepalive_timeout"`
	MaxRetries               int     `json:"max_retries"`
	TargetConnectTimeout     float64 `json:"target_connect_timeout"`
	GoSenderRequired         bool    `json:"go_downstream_sender_required"`
	GoDownstreamSenderEnable bool    `json:"go_downstream_sender_enabled"`
}

func defaultConfig() config {
	return config{
		VPSInIP:                 "1.2.3.4",
		SpoofIP:                 "5.6.7.8",
		UDPPort:                 10808,
		ControlPort:             8888,
		ListenHost:              "0.0.0.0",
		UDPMTU:                  1200,
		ResendInterval:          1.0,
		RetransmitScanInterval:  0.05,
		MaxResendsPerTick:       64,
		ResendBackoffFactor:     1.4,
		MaxPendingChunks:        8192,
		TargetRecvSize:          65536,
		SocketBufferBytes:       1 << 20,
		UDPPlainFallbackEnabled: true,
		SessionCloseGrace:       0.8,
		KeepaliveInterval:       3.0,
		KeepaliveTimeout:        10.0,
		MaxRetries:              5,
		TargetConnectTimeout:    10.0,
	}
}

func loadConfig(path string) (config, error) {
	cfg := defaultConfig()

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}

	if env := os.Getenv("VPS_IN_IP"); env != "" {
		cfg.VPSInIP = env
	}
	if env := os.Getenv("SPOOF_IP"); env != "" {
		cfg.SpoofIP = env
	}

	return cfg, nil
}

type tcpHeader struct {
	Magic      [4]byte
	Version    uint8
	Type       uint8
	SessionID  uint32
	PayloadLen uint32
}

type udpHeader struct {
	Magic     [4]byte
	SessionID uint32
	SeqNum    uint32
	Flags     uint8
	Len       uint16
}

type bufferedChunk struct {
	Payload       []byte
	Attempts      int
	LastSent      time.Time
	RetryInterval time.Duration
	NextRetryAt   time.Time
}

type sessionState struct {
	ID         uint32
	Control    net.Conn
	Target     net.Conn
	ClientAddr string
	TargetHost string
	TargetPort int

	SendMu sync.Mutex
	Mu     sync.Mutex

	Closed    bool
	LastPong  time.Time
	AckedUpto int64
	NextSeq   uint32

	ChunksSent    uint64
	BytesToTarget uint64
	BytesToIN     uint64
	AcksReceived  uint64
	LastAckSeq    int64

	FirstChunkSentAt   time.Time
	FirstAckReceivedAt time.Time
	TxChunkLimit       int
	SendBuffer         map[uint32]*bufferedChunk
}

func (s *sessionState) isClosed() bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Closed
}

type runtimeState struct {
	cfg config

	spoofDestIP net.IP
	tx          transport.Transport
	plainUDP    *net.UDPConn

	sessionsMu sync.Mutex
	sessions   map[uint32]*sessionState

	statsMu      sync.Mutex
	accepted     int
	lastCloseMsg string
}

func newRuntime(cfg config) *runtimeState {
	return &runtimeState{
		cfg:      cfg,
		sessions: make(map[uint32]*sessionState),
	}
}

func (rt *runtimeState) registerSession(s *sessionState) {
	rt.sessionsMu.Lock()
	rt.sessions[s.ID] = s
	rt.sessionsMu.Unlock()

	rt.statsMu.Lock()
	rt.accepted++
	rt.statsMu.Unlock()
}

func (rt *runtimeState) unregisterSession(id uint32, reason string) {
	rt.sessionsMu.Lock()
	delete(rt.sessions, id)
	rt.sessionsMu.Unlock()

	rt.statsMu.Lock()
	rt.lastCloseMsg = reason
	rt.statsMu.Unlock()
}

func (rt *runtimeState) logStatusLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rt.sessionsMu.Lock()
		snap := make([]*sessionState, 0, len(rt.sessions))
		for _, s := range rt.sessions {
			snap = append(snap, s)
		}
		rt.sessionsMu.Unlock()

		rt.statsMu.Lock()
		accepted := rt.accepted
		lastClose := rt.lastCloseMsg
		rt.statsMu.Unlock()

		if len(snap) == 0 {
			if lastClose == "" {
				log.Printf("status active_sessions=0 accepted_sessions=%d waiting_for_in_connection=1", accepted)
			} else {
				log.Printf("status active_sessions=0 accepted_sessions=%d last_close=%s", accepted, lastClose)
			}
			continue
		}

		var totalChunks uint64
		var totalToTarget uint64
		var totalToIN uint64
		var waitingAck int
		var pending int
		latencies := make([]int64, 0, len(snap))

		for _, s := range snap {
			s.Mu.Lock()
			totalChunks += s.ChunksSent
			totalToTarget += s.BytesToTarget
			totalToIN += s.BytesToIN
			if s.ChunksSent > 0 && s.AcksReceived == 0 {
				waitingAck++
			}
			pending += len(s.SendBuffer)
			if !s.FirstChunkSentAt.IsZero() && !s.FirstAckReceivedAt.IsZero() {
				latencies = append(latencies, s.FirstAckReceivedAt.Sub(s.FirstChunkSentAt).Milliseconds())
			}
			s.Mu.Unlock()
		}

		avgAck := int64(-1)
		if len(latencies) > 0 {
			var sum int64
			for _, l := range latencies {
				sum += l
			}
			avgAck = sum / int64(len(latencies))
		}

		log.Printf(
			"status active_sessions=%d accepted_sessions=%d total_chunks=%d bytes_to_target=%d bytes_to_in=%d sessions_waiting_ack=%d pending_chunks=%d avg_first_ack_ms=%d",
			len(snap),
			accepted,
			totalChunks,
			totalToTarget,
			totalToIN,
			waitingAck,
			pending,
			avgAck,
		)
	}
}

func recvExact(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func recvFrame(r io.Reader) (uint8, uint32, []byte, error) {
	hdrBytes, err := recvExact(r, 14)
	if err != nil {
		return 0, 0, nil, err
	}

	var hdr tcpHeader
	copy(hdr.Magic[:], hdrBytes[0:4])
	hdr.Version = hdrBytes[4]
	hdr.Type = hdrBytes[5]
	hdr.SessionID = binary.BigEndian.Uint32(hdrBytes[6:10])
	hdr.PayloadLen = binary.BigEndian.Uint32(hdrBytes[10:14])

	if string(hdr.Magic[:]) != magic {
		return 0, 0, nil, errors.New("invalid control frame magic")
	}
	if hdr.Version != version {
		return 0, 0, nil, fmt.Errorf("unsupported protocol version %d", hdr.Version)
	}

	if hdr.PayloadLen == 0 {
		return hdr.Type, hdr.SessionID, nil, nil
	}
	payload, err := recvExact(r, int(hdr.PayloadLen))
	if err != nil {
		return 0, 0, nil, err
	}
	return hdr.Type, hdr.SessionID, payload, nil
}

func sendFrame(w io.Writer, typ uint8, sessionID uint32, payload []byte, lock *sync.Mutex) error {
	if payload == nil {
		payload = []byte{}
	}

	frame := make([]byte, 14+len(payload))
	copy(frame[0:4], []byte(magic))
	frame[4] = version
	frame[5] = typ
	binary.BigEndian.PutUint32(frame[6:10], sessionID)
	binary.BigEndian.PutUint32(frame[10:14], uint32(len(payload)))
	copy(frame[14:], payload)

	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}

	_, err := w.Write(frame)
	return err
}

func closeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
}

func sendUDPChunk(rt *runtimeState, s *sessionState, seq uint32, payload []byte, flags uint8) error {
	packet := make([]byte, 15+len(payload))
	copy(packet[0:4], []byte(magic))
	binary.BigEndian.PutUint32(packet[4:8], s.ID)
	binary.BigEndian.PutUint32(packet[8:12], seq)
	packet[12] = flags
	binary.BigEndian.PutUint16(packet[13:15], uint16(len(payload)))
	copy(packet[15:], payload)

	spoofErr := error(nil)
	if rt.tx != nil {
		if err := rt.tx.Send(packet, rt.spoofDestIP, uint16(rt.cfg.UDPPort)); err == nil {
			return nil
		} else {
			spoofErr = err
		}
	}

	if rt.cfg.GoSenderRequired {
		if spoofErr == nil {
			spoofErr = errors.New("spoof sender unavailable")
		}
		return fmt.Errorf("spoof send required and failed: %w", spoofErr)
	}

	if rt.cfg.UDPPlainFallbackEnabled && rt.plainUDP != nil {
		if _, err := rt.plainUDP.Write(packet); err == nil {
			return nil
		}
	}

	if spoofErr != nil {
		return spoofErr
	}
	return errors.New("failed to send UDP chunk")
}

func waitForPendingAcks(s *sessionState, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.Mu.Lock()
		closed := s.Closed
		pending := len(s.SendBuffer)
		s.Mu.Unlock()
		if closed || pending == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func closeSession(rt *runtimeState, s *sessionState, reason string) {
	s.Mu.Lock()
	if s.Closed {
		s.Mu.Unlock()
		return
	}
	s.Closed = true
	bytesToTarget := s.BytesToTarget
	bytesToIN := s.BytesToIN
	chunksSent := s.ChunksSent
	ackedUpto := s.AckedUpto
	acksReceived := s.AcksReceived
	lastAck := s.LastAckSeq
	pending := len(s.SendBuffer)
	firstChunkAt := s.FirstChunkSentAt
	firstAckAt := s.FirstAckReceivedAt
	s.Mu.Unlock()

	latency := int64(-1)
	if !firstChunkAt.IsZero() && !firstAckAt.IsZero() {
		latency = firstAckAt.Sub(firstChunkAt).Milliseconds()
	}

	rt.unregisterSession(s.ID, reason)
	log.Printf(
		"session=%d closing reason=%s bytes_to_target=%d bytes_to_in=%d chunks_sent=%d acked_upto=%d acks_received=%d last_ack_seq=%d pending_chunks=%d first_ack_latency_ms=%d",
		s.ID,
		reason,
		bytesToTarget,
		bytesToIN,
		chunksSent,
		ackedUpto,
		acksReceived,
		lastAck,
		pending,
		latency,
	)

	closeConn(s.Control)
	closeConn(s.Target)
}

func sendChunkWithTracking(rt *runtimeState, s *sessionState, payload []byte) error {
	for {
		s.Mu.Lock()
		if s.Closed {
			s.Mu.Unlock()
			return errors.New("session closed")
		}
		if len(s.SendBuffer) < rt.cfg.MaxPendingChunks {
			seq := s.NextSeq
			s.NextSeq++
			now := time.Now()
			if s.FirstChunkSentAt.IsZero() {
				s.FirstChunkSentAt = now
			}
			s.SendBuffer[seq] = &bufferedChunk{
				Payload:       append([]byte(nil), payload...),
				Attempts:      1,
				LastSent:      now,
				RetryInterval: time.Duration(float64(time.Second) * rt.cfg.ResendInterval),
				NextRetryAt:   now.Add(time.Duration(float64(time.Second) * rt.cfg.ResendInterval)),
			}
			s.ChunksSent++
			s.Mu.Unlock()

			if err := sendUDPChunk(rt, s, seq, payload, 0); err != nil {
				return err
			}
			return nil
		}
		s.Mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
}

func sendControlReady(s *sessionState, info map[string]interface{}) error {
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return sendFrame(s.Control, typeReady, s.ID, payload, &s.SendMu)
}

func sendControlError(s *sessionState, msg string) {
	_ = sendFrame(s.Control, typeError, s.ID, []byte(msg), &s.SendMu)
}

func handleControlReader(rt *runtimeState, s *sessionState) {
	for {
		if s.isClosed() {
			return
		}

		typ, sid, payload, err := recvFrame(s.Control)
		if err != nil {
			if !s.isClosed() {
				closeSession(rt, s, fmt.Sprintf("control reader failed: %v", err))
			}
			return
		}

		if sid != s.ID {
			log.Printf("session=%d received frame for mismatched session=%d type=%d", s.ID, sid, typ)
			continue
		}

		switch typ {
		case typeData:
			if _, err := s.Target.Write(payload); err != nil {
				closeSession(rt, s, fmt.Sprintf("target write failed: %v", err))
				return
			}
			s.Mu.Lock()
			s.BytesToTarget += uint64(len(payload))
			s.Mu.Unlock()

		case typePing:
			if err := sendFrame(s.Control, typePong, s.ID, payload, &s.SendMu); err != nil {
				closeSession(rt, s, fmt.Sprintf("pong send failed: %v", err))
				return
			}

		case typePong:
			s.Mu.Lock()
			s.LastPong = time.Now()
			s.Mu.Unlock()

		case typeAck:
			now := time.Now()
			s.Mu.Lock()
			s.AcksReceived++
			if s.FirstAckReceivedAt.IsZero() {
				s.FirstAckReceivedAt = now
			}

			if len(payload) == 4 {
				ackSeq := binary.BigEndian.Uint32(payload)
				s.LastAckSeq = int64(ackSeq)
				if int64(ackSeq) > s.AckedUpto {
					for seq := range s.SendBuffer {
						if seq <= ackSeq {
							delete(s.SendBuffer, seq)
						}
					}
					s.AckedUpto = int64(ackSeq)
				}
				s.Mu.Unlock()
				continue
			}

			if len(payload) == 12 {
				ackBaseRaw := binary.BigEndian.Uint32(payload[0:4])
				ackMask := binary.BigEndian.Uint64(payload[4:12])
				ackBase := int64(ackBaseRaw)
				if ackBaseRaw == 0xFFFFFFFF {
					ackBase = -1
				}
				s.LastAckSeq = ackBase
				if ackBase > s.AckedUpto {
					s.AckedUpto = ackBase
				}
				for seq := range s.SendBuffer {
					if int64(seq) <= ackBase {
						delete(s.SendBuffer, seq)
						continue
					}
					delta := int64(seq) - ackBase
					if delta >= 1 && delta <= ackSackWindow {
						if (ackMask & (uint64(1) << (delta - 1))) != 0 {
							delete(s.SendBuffer, seq)
						}
					}
				}
			}
			s.Mu.Unlock()

		case typeClose:
			closeSession(rt, s, "peer closed session")
			return

		case typeError:
			msg := "unknown error"
			if len(payload) > 0 {
				msg = string(payload)
			}
			closeSession(rt, s, fmt.Sprintf("peer error: %s", msg))
			return
		}
	}
}

func handleTargetReader(rt *runtimeState, s *sessionState) {
	buf := make([]byte, rt.cfg.TargetRecvSize)
	for {
		if s.isClosed() {
			return
		}

		n, err := s.Target.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			closeSession(rt, s, fmt.Sprintf("target read failed: %v", err))
			return
		}
		if n <= 0 {
			continue
		}

		chunkLimit := s.TxChunkLimit
		if chunkLimit < 512 {
			chunkLimit = 512
		}

		data := buf[:n]
		for off := 0; off < len(data); off += chunkLimit {
			end := off + chunkLimit
			if end > len(data) {
				end = len(data)
			}
			chunk := data[off:end]
			if err := sendChunkWithTracking(rt, s, chunk); err != nil {
				closeSession(rt, s, fmt.Sprintf("UDP send failed: %v", err))
				return
			}
			s.Mu.Lock()
			s.BytesToIN += uint64(len(chunk))
			s.Mu.Unlock()
		}
	}

	if !s.isClosed() {
		waitForPendingAcks(s, time.Duration(float64(time.Second)*rt.cfg.SessionCloseGrace))
		sendControlError(s, "target closed connection")
		_ = sendFrame(s.Control, typeClose, s.ID, []byte("target closed"), &s.SendMu)
		closeSession(rt, s, "target closed connection")
	}
}

func handleRetransmissions(rt *runtimeState, s *sessionState) {
	interval := time.Duration(float64(time.Second) * rt.cfg.RetransmitScanInterval)
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if s.isClosed() {
			return
		}

		now := time.Now()
		type resendItem struct {
			Seq   uint32
			Chunk *bufferedChunk
		}

		resends := make([]resendItem, 0)
		s.Mu.Lock()
		for seq, b := range s.SendBuffer {
			if int64(seq) <= s.AckedUpto {
				delete(s.SendBuffer, seq)
				continue
			}
			if now.After(b.NextRetryAt) || now.Equal(b.NextRetryAt) {
				resends = append(resends, resendItem{Seq: seq, Chunk: b})
			}
		}
		s.Mu.Unlock()

		sort.Slice(resends, func(i, j int) bool { return resends[i].Seq < resends[j].Seq })
		if len(resends) > rt.cfg.MaxResendsPerTick {
			resends = resends[:rt.cfg.MaxResendsPerTick]
		}

		for _, it := range resends {
			if s.isClosed() {
				return
			}

			s.Mu.Lock()
			cur, ok := s.SendBuffer[it.Seq]
			if !ok {
				s.Mu.Unlock()
				continue
			}
			cur.Attempts++
			attempts := cur.Attempts
			cur.LastSent = now
			next := time.Duration(float64(cur.RetryInterval) * rt.cfg.ResendBackoffFactor)
			if next > 3*time.Second {
				next = 3 * time.Second
			}
			cur.RetryInterval = next
			cur.NextRetryAt = now.Add(next)
			s.Mu.Unlock()

			if attempts > rt.cfg.MaxRetries {
				closeSession(rt, s, fmt.Sprintf("retransmit limit reached for seq %d", it.Seq))
				return
			}

			if err := sendUDPChunk(rt, s, it.Seq, it.Chunk.Payload, 0); err != nil {
				closeSession(rt, s, fmt.Sprintf("UDP resend failed: %v", err))
				return
			}
		}
	}
}

func handleKeepalive(rt *runtimeState, s *sessionState) {
	interval := time.Duration(float64(time.Second) * rt.cfg.KeepaliveInterval)
	timeout := time.Duration(float64(time.Second) * rt.cfg.KeepaliveTimeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if s.isClosed() {
			return
		}

		stamp := make([]byte, 8)
		binary.BigEndian.PutUint64(stamp, uint64(time.Now().UnixNano()))
		if err := sendFrame(s.Control, typePing, s.ID, stamp, &s.SendMu); err != nil {
			closeSession(rt, s, fmt.Sprintf("keepalive send failed: %v", err))
			return
		}

		s.Mu.Lock()
		last := s.LastPong
		s.Mu.Unlock()
		if time.Since(last) > timeout {
			closeSession(rt, s, "keepalive timeout")
			return
		}
	}
}

func handleControlConn(rt *runtimeState, control net.Conn, clientAddr string) {
	defer closeConn(control)

	_ = control.SetReadDeadline(time.Now().Add(time.Duration(float64(time.Second) * rt.cfg.TargetConnectTimeout)))
	typ, sid, payload, err := recvFrame(control)
	if err != nil {
		log.Printf("control connection from %s failed: %v", clientAddr, err)
		return
	}
	if typ != typeHello {
		log.Printf("control connection from %s failed: expected HELLO got type=%d", clientAddr, typ)
		return
	}

	var hello struct {
		TargetHost       string `json:"target_host"`
		TargetPort       int    `json:"target_port"`
		UDPMTU           int    `json:"udp_mtu"`
		MaxUDPPayload    int    `json:"max_udp_payload"`
		AckSackWindow    int    `json:"ack_sack_window"`
		ClientAddr       string `json:"client_addr"`
	}
	if err := json.Unmarshal(payload, &hello); err != nil {
		log.Printf("control connection from %s invalid hello: %v", clientAddr, err)
		return
	}

	if hello.TargetHost == "" || hello.TargetPort <= 0 || hello.TargetPort > 65535 {
		_ = sendFrame(control, typeError, sid, []byte("invalid target in hello"), nil)
		return
	}

	maxPayload := rt.cfg.UDPMTU - 20 - 8 - 15
	if hello.MaxUDPPayload > 0 && hello.MaxUDPPayload < maxPayload {
		maxPayload = hello.MaxUDPPayload
	}
	if maxPayload < 256 {
		_ = sendFrame(control, typeError, sid, []byte("invalid negotiated payload"), nil)
		return
	}

	targetAddr := net.JoinHostPort(hello.TargetHost, fmt.Sprintf("%d", hello.TargetPort))
	dialer := net.Dialer{Timeout: time.Duration(float64(time.Second) * rt.cfg.TargetConnectTimeout)}
	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		_ = sendFrame(control, typeError, sid, []byte(err.Error()), nil)
		return
	}
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetReadBuffer(rt.cfg.SocketBufferBytes)
		_ = tcpConn.SetWriteBuffer(rt.cfg.SocketBufferBytes)
	}

	_ = control.SetReadDeadline(time.Time{})

	s := &sessionState{
		ID:           sid,
		Control:      control,
		Target:       targetConn,
		ClientAddr:   clientAddr,
		TargetHost:   hello.TargetHost,
		TargetPort:   hello.TargetPort,
		LastPong:     time.Now(),
		AckedUpto:    -1,
		LastAckSeq:   -1,
		TxChunkLimit: maxPayload,
		SendBuffer:   make(map[uint32]*bufferedChunk),
	}
	rt.registerSession(s)

	if err := sendControlReady(s, map[string]interface{}{
		"status":             "ready",
		"target_host":        hello.TargetHost,
		"target_port":        hello.TargetPort,
		"udp_mtu":            rt.cfg.UDPMTU,
		"max_udp_payload":    rt.cfg.UDPMTU - 20 - 8 - 15,
		"negotiated_payload": maxPayload,
		"ack_sack_window":    ackSackWindow,
		"spoof_ip":           rt.cfg.SpoofIP,
	}); err != nil {
		closeSession(rt, s, fmt.Sprintf("failed to send READY: %v", err))
		return
	}

	go handleControlReader(rt, s)
	go handleTargetReader(rt, s)
	go handleRetransmissions(rt, s)
	go handleKeepalive(rt, s)

	for {
		time.Sleep(200 * time.Millisecond)
		if s.isClosed() {
			return
		}
	}
}

func initSenders(rt *runtimeState) error {
	srcIP := net.ParseIP(rt.cfg.SpoofIP)
	if srcIP == nil || srcIP.To4() == nil {
		return fmt.Errorf("invalid spoof_ip: %s", rt.cfg.SpoofIP)
	}
	dstIP := net.ParseIP(rt.cfg.VPSInIP)
	if dstIP == nil || dstIP.To4() == nil {
		return fmt.Errorf("invalid vps_in_ip: %s", rt.cfg.VPSInIP)
	}
	rt.spoofDestIP = dstIP

	tcfg := &transport.Config{
		SourceIP:   srcIP,
		ListenPort: uint16(rt.cfg.UDPPort),
		BufferSize: rt.cfg.SocketBufferBytes,
		MTU:        rt.cfg.UDPMTU,
	}

	tx, err := transport.NewUDPTransport(tcfg)
	if err == nil {
		rt.tx = tx
		log.Printf("spoof sender ready source=%s dest=%s:%d", rt.cfg.SpoofIP, rt.cfg.VPSInIP, rt.cfg.UDPPort)
	} else {
		log.Printf("spoof sender unavailable: %v", err)
		if rt.cfg.GoSenderRequired {
			return fmt.Errorf("spoof sender required but unavailable: %w", err)
		}
	}

	if rt.cfg.UDPPlainFallbackEnabled {
		addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", rt.cfg.VPSInIP, rt.cfg.UDPPort))
		if err == nil {
			if conn, derr := net.DialUDP("udp4", nil, addr); derr == nil {
				rt.plainUDP = conn
				_ = rt.plainUDP.SetWriteBuffer(rt.cfg.SocketBufferBytes)
			}
		}
	}

	if rt.tx == nil && rt.plainUDP == nil {
		return errors.New("no downstream sender available")
	}
	return nil
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "c", "out_config.json", "path to out_config.json")
	flag.Parse()

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config %s: %v", configPath, err)
	}

	log.Printf("configured UDP MTU=%d max payload=%d", cfg.UDPMTU, cfg.UDPMTU-20-8-15)
	log.Printf("raw UDP spoof source=%s destination=%s:%d", cfg.SpoofIP, cfg.VPSInIP, cfg.UDPPort)

	rt := newRuntime(cfg)
	if err := initSenders(rt); err != nil {
		log.Fatalf("failed to init senders: %v", err)
	}
	defer func() {
		if rt.tx != nil {
			_ = rt.tx.Close()
		}
		if rt.plainUDP != nil {
			_ = rt.plainUDP.Close()
		}
	}()

	go rt.logStatusLoop()

	listenAddr := net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", cfg.ControlPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen failed on %s: %v", listenAddr, err)
	}
	defer ln.Close()

	log.Printf("listening for control TCP on %s", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("accept failed: %v", err)
			}
			continue
		}

		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetReadBuffer(cfg.SocketBufferBytes)
			_ = tcp.SetWriteBuffer(cfg.SocketBufferBytes)
		}

		clientAddr := conn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(clientAddr); err == nil {
			clientAddr = host
		}
		go handleControlConn(rt, conn, clientAddr)
	}
}

func init() {
	log.SetFlags(log.LstdFlags)
	// Guard against accidental protocol drift.
	if !bytes.Equal([]byte(magic), []byte{'H', 'T', 'U', 'N'}) {
		panic("invalid magic")
	}
}