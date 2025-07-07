package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// 协议常量
const (
	MaxPayloadSize = 1200
	WindowSize     = 32
	DefaultTimeout = 10 * time.Second
	MaxRetries     = 5
	ICMPProtocol   = 1
)

// 消息类型
const (
	MsgTypeData  = 0x01
	MsgTypeACK   = 0x02
	MsgTypeStart = 0x03
	MsgTypeEnd   = 0x04
)

// ICMP协议头
type ICMPHeader struct {
	Type      uint8
	SessionID uint32
	SeqID     uint16
	TotalSeq  uint16
	Checksum  uint16
	Length    uint16
}

// 序列化协议头
func (h *ICMPHeader) Marshal() []byte {
	buf := make([]byte, 13)
	buf[0] = h.Type
	binary.BigEndian.PutUint32(buf[1:5], h.SessionID)
	binary.BigEndian.PutUint16(buf[5:7], h.SeqID)
	binary.BigEndian.PutUint16(buf[7:9], h.TotalSeq)
	binary.BigEndian.PutUint16(buf[9:11], h.Checksum)
	binary.BigEndian.PutUint16(buf[11:13], h.Length)
	return buf
}

// 反序列化协议头
func UnmarshalICMPHeader(data []byte) *ICMPHeader {
	if len(data) < 13 {
		return nil
	}
	return &ICMPHeader{
		Type:      data[0],
		SessionID: binary.BigEndian.Uint32(data[1:5]),
		SeqID:     binary.BigEndian.Uint16(data[5:7]),
		TotalSeq:  binary.BigEndian.Uint16(data[7:9]),
		Checksum:  binary.BigEndian.Uint16(data[9:11]),
		Length:    binary.BigEndian.Uint16(data[11:13]),
	}
}

// 计算校验和
func calculateChecksum(data []byte) uint16 {
	return uint16(crc32.ChecksumIEEE(data) & 0xFFFF)
}

// 计算文件MD5
func calculateFileMD5(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// 传输会话
type Session struct {
	ID         uint32
	Window     [WindowSize]bool
	Acked      uint16
	LastSeq    uint16
	DataBuffer map[uint16][]byte
	File       *os.File
	Lock       sync.Mutex
	TotalSeq   uint16
	Filename   string
	FileSize   int64
	Received   int64
	StartTime  time.Time
}

// ACK信息
type ACKInfo struct {
	SessionID uint32
	SeqID     uint16
	Received  bool
	Timestamp time.Time
}

// 客户端
type Client struct {
	ServerIP   net.IP
	SessionID  uint32
	Retry      int
	Timeout    time.Duration
	conn       net.Conn
	listenConn *icmp.PacketConn
	Progress   *progressbar.ProgressBar
	ackMap     sync.Map
	ackChan    chan ACKInfo
	done       chan bool
}

// 创建客户端
func NewClient(serverIP string) (*Client, error) {
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid server IP: %s", serverIP)
	}

	// 生成随机会话ID
	sessionBytes := make([]byte, 4)
	rand.Read(sessionBytes)
	sessionID := binary.BigEndian.Uint32(sessionBytes)

	// 创建发送连接
	conn, err := net.Dial("ip4:icmp", serverIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP connection: %v", err)
	}

	// 创建接收连接
	listenConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create ICMP listen connection: %v", err)
	}

	client := &Client{
		ServerIP:   ip,
		SessionID:  sessionID,
		Retry:      MaxRetries,
		Timeout:    DefaultTimeout,
		conn:       conn,
		listenConn: listenConn,
		ackChan:    make(chan ACKInfo, 100),
		done:       make(chan bool),
	}

	// 启动ACK监听
	go client.listenACK()

	return client, nil
}

// 监听ACK
func (c *Client) listenACK() {
	buffer := make([]byte, 1500)
	for {
		select {
		case <-c.done:
			return
		default:
			c.listenConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, peer, err := c.listenConn.ReadFrom(buffer)
			if err != nil {
				continue
			}

			// 检查是否来自服务器
			if !peer.(*net.IPAddr).IP.Equal(c.ServerIP) {
				continue
			}

			// 解析ICMP消息
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buffer[:n])
			if err != nil {
				continue
			}

			// 处理Echo Reply
			if echo, ok := msg.Body.(*icmp.Echo); ok {
				if echo.ID == int(c.SessionID&0xFFFF) {
					c.handleACK(echo.Data)
				}
			}
		}
	}
}

// 处理ACK
func (c *Client) handleACK(data []byte) {
	if len(data) < 13 {
		return
	}

	header := UnmarshalICMPHeader(data)
	if header == nil || header.Type != MsgTypeACK || header.SessionID != c.SessionID {
		return
	}

	// 记录ACK
	ackInfo := ACKInfo{
		SessionID: header.SessionID,
		SeqID:     header.SeqID,
		Received:  true,
		Timestamp: time.Now(),
	}

	c.ackMap.Store(header.SeqID, ackInfo)

	select {
	case c.ackChan <- ackInfo:
	default:
	}
}

// 等待ACK
func (c *Client) waitForACK(seqID uint16, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if ack, ok := c.ackMap.Load(seqID); ok {
			ackInfo := ack.(ACKInfo)
			if ackInfo.Received {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// 发送文件
func (c *Client) SendFile(filePath string) error {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}

	fileSize := fileInfo.Size()
	filename := filepath.Base(filePath)

	// 计算文件MD5
	fileMD5, err := calculateFileMD5(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate file MD5: %v", err)
	}

	// 计算总分片数
	totalChunks := int((fileSize + MaxPayloadSize - 1) / MaxPayloadSize)

	fmt.Printf("Sending file: %s\n", filename)
	fmt.Printf("File size: %d bytes\n", fileSize)
	fmt.Printf("Total chunks: %d\n", totalChunks)
	fmt.Printf("File MD5: %s\n", fileMD5)

	// 创建进度条
	c.Progress = progressbar.NewOptions64(
		fileSize,
		progressbar.OptionSetWidth(50),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription(fmt.Sprintf("Sending %s", filename)),
		progressbar.OptionShowCount(),
	)

	// 发送开始包
	startData := fmt.Sprintf("%s|%d|%s", filename, fileSize, fileMD5)
	err = c.sendPacketWithRetry(MsgTypeStart, 0, uint16(totalChunks), []byte(startData))
	if err != nil {
		return fmt.Errorf("failed to send start packet: %v", err)
	}

	// 发送文件数据
	buffer := make([]byte, MaxPayloadSize)
	for seqID := uint16(1); seqID <= uint16(totalChunks); seqID++ {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read file: %v", err)
		}
		if n == 0 {
			break
		}

		// 发送数据包
		err = c.sendPacketWithRetry(MsgTypeData, seqID, uint16(totalChunks), buffer[:n])
		if err != nil {
			return fmt.Errorf("failed to send data packet %d: %v", seqID, err)
		}

		// 更新进度
		c.Progress.Add(n)
	}

	// 发送结束包
	err = c.sendPacketWithRetry(MsgTypeEnd, uint16(totalChunks+1), uint16(totalChunks), nil)
	if err != nil {
		return fmt.Errorf("failed to send end packet: %v", err)
	}

	c.Progress.Finish()
	fmt.Printf("\nFile %s sent successfully!\n", filename)
	return nil
}

// 带重试的发送包
func (c *Client) sendPacketWithRetry(msgType uint8, seqID, totalSeq uint16, payload []byte) error {
	for attempt := 0; attempt < c.Retry; attempt++ {
		// 发送包
		err := c.sendPacket(msgType, seqID, totalSeq, payload)
		if err != nil {
			log.Printf("Send attempt %d failed: %v", attempt+1, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		// 等待ACK
		if c.waitForACK(seqID, c.Timeout) {
			return nil
		}

		log.Printf("ACK timeout for seq %d, attempt %d", seqID, attempt+1)
		time.Sleep(time.Duration(attempt) * time.Second)
	}

	return fmt.Errorf("failed to send packet after %d attempts", c.Retry)
}

// 发送数据包
func (c *Client) sendPacket(msgType uint8, seqID, totalSeq uint16, payload []byte) error {
	header := &ICMPHeader{
		Type:      msgType,
		SessionID: c.SessionID,
		SeqID:     seqID,
		TotalSeq:  totalSeq,
		Length:    uint16(len(payload)),
	}

	if payload != nil {
		header.Checksum = calculateChecksum(payload)
	}

	headerBytes := header.Marshal()

	// 构造ICMP消息
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(c.SessionID & 0xFFFF),
			Seq:  int(seqID),
			Data: append(headerBytes, payload...),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %v", err)
	}

	// 发送数据包
	_, err = c.conn.Write(msgBytes)
	if err != nil {
		return fmt.Errorf("failed to write to connection: %v", err)
	}

	return nil
}

// 关闭连接
func (c *Client) Close() error {
	close(c.done)
	c.listenConn.Close()
	return c.conn.Close()
}

// 服务端
type Server struct {
	StorageDir string
	Sessions   sync.Map
	conn       *icmp.PacketConn
}

// 创建服务端
func NewServer(storageDir string) (*Server, error) {
	// 创建存储目录
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %v", err)
	}

	// 监听ICMP连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen on ICMP: %v", err)
	}

	return &Server{
		StorageDir: storageDir,
		conn:       conn,
	}, nil
}

// 启动服务器
func (s *Server) Start() error {
	fmt.Printf("ICMP server started, listening on all interfaces\n")
	fmt.Printf("Storage directory: %s\n", s.StorageDir)

	buffer := make([]byte, 1500)
	for {
		n, peer, err := s.conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Error reading from connection: %v", err)
			continue
		}

		// 解析ICMP消息
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buffer[:n])
		if err != nil {
			continue
		}

		// 处理Echo消息
		if echo, ok := msg.Body.(*icmp.Echo); ok {
			go s.handlePacket(echo.Data, peer, echo.ID, echo.Seq)
		}
	}
}

// 处理数据包
func (s *Server) handlePacket(data []byte, peer net.Addr, echoID, echoSeq int) {
	if len(data) < 13 {
		return
	}

	header := UnmarshalICMPHeader(data)
	if header == nil {
		return
	}

	payload := data[13:]
	if len(payload) != int(header.Length) {
		return
	}

	// 验证校验和
	if header.Length > 0 && header.Checksum != calculateChecksum(payload) {
		log.Printf("Checksum mismatch for session %d, seq %d", header.SessionID, header.SeqID)
		return
	}

	switch header.Type {
	case MsgTypeStart:
		s.handleStartPacket(header, payload, peer)
	case MsgTypeData:
		s.handleDataPacket(header, payload, peer)
	case MsgTypeEnd:
		s.handleEndPacket(header, peer)
	}
}

// 处理开始包
func (s *Server) handleStartPacket(header *ICMPHeader, payload []byte, peer net.Addr) {
	startData := string(payload)
	parts := bytes.Split([]byte(startData), []byte("|"))
	if len(parts) != 3 {
		log.Printf("Invalid start packet format")
		return
	}

	filename := string(parts[0])
	fileSize := binary.BigEndian.Uint64(append(make([]byte, 8-len(parts[1])), parts[1]...))
	fileMD5 := string(parts[2])

	filepath := filepath.Join(s.StorageDir, filename)

	// 创建文件
	file, err := os.Create(filepath)
	if err != nil {
		log.Printf("Failed to create file %s: %v", filename, err)
		return
	}

	session := &Session{
		ID:         header.SessionID,
		File:       file,
		DataBuffer: make(map[uint16][]byte),
		TotalSeq:   header.TotalSeq,
		Filename:   filename,
		FileSize:   int64(fileSize),
		StartTime:  time.Now(),
	}

	s.Sessions.Store(header.SessionID, session)

	fmt.Printf("Started receiving file: %s (size: %d bytes, chunks: %d, MD5: %s)\n",
		filename, fileSize, header.TotalSeq, fileMD5)

	// 发送ACK
	s.sendACK(header.SessionID, header.SeqID, peer)
}

// 处理数据包
func (s *Server) handleDataPacket(header *ICMPHeader, payload []byte, peer net.Addr) {
	sessionInterface, ok := s.Sessions.Load(header.SessionID)
	if !ok {
		return
	}

	session := sessionInterface.(*Session)
	session.Lock.Lock()
	defer session.Lock.Unlock()

	// 检查是否已经接收过这个包
	if _, exists := session.DataBuffer[header.SeqID]; exists {
		// 发送ACK（可能是重复包）
		s.sendACK(header.SessionID, header.SeqID, peer)
		return
	}

	// 存储数据
	session.DataBuffer[header.SeqID] = make([]byte, len(payload))
	copy(session.DataBuffer[header.SeqID], payload)
	session.Received += int64(len(payload))

	// 写入连续的数据块
	for seq := session.LastSeq + 1; seq <= header.TotalSeq; seq++ {
		if data, exists := session.DataBuffer[seq]; exists {
			session.File.Write(data)
			delete(session.DataBuffer, seq)
			session.LastSeq = seq
		} else {
			break
		}
	}

	// 显示进度
	progress := float64(session.Received) / float64(session.FileSize) * 100
	fmt.Printf("Session %d: %.1f%% (%d/%d bytes)\n",
		header.SessionID, progress, session.Received, session.FileSize)

	// 发送ACK
	s.sendACK(header.SessionID, header.SeqID, peer)
}

// 处理结束包
func (s *Server) handleEndPacket(header *ICMPHeader, peer net.Addr) {
	sessionInterface, ok := s.Sessions.Load(header.SessionID)
	if !ok {
		return
	}

	session := sessionInterface.(*Session)
	session.Lock.Lock()
	defer session.Lock.Unlock()

	// 写入剩余的数据块
	for seq := session.LastSeq + 1; seq <= header.TotalSeq; seq++ {
		if data, exists := session.DataBuffer[seq]; exists {
			session.File.Write(data)
			delete(session.DataBuffer, seq)
			session.LastSeq = seq
		}
	}

	// 关闭文件
	session.File.Close()

	// 验证文件完整性
	filepath := filepath.Join(s.StorageDir, session.Filename)
	receivedMD5, err := calculateFileMD5(filepath)
	if err != nil {
		log.Printf("Failed to calculate received file MD5: %v", err)
	} else {
		fmt.Printf("File %s received successfully!\n", session.Filename)
		fmt.Printf("Received MD5: %s\n", receivedMD5)
		fmt.Printf("Transfer time: %v\n", time.Since(session.StartTime))
	}

	// 清理会话
	s.Sessions.Delete(header.SessionID)

	// 发送ACK
	s.sendACK(header.SessionID, header.SeqID, peer)
}

// 发送ACK
func (s *Server) sendACK(sessionID uint32, seqID uint16, peer net.Addr) {
	header := &ICMPHeader{
		Type:      MsgTypeACK,
		SessionID: sessionID,
		SeqID:     seqID,
		TotalSeq:  0,
		Length:    0,
	}

	headerBytes := header.Marshal()

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(sessionID & 0xFFFF),
			Seq:  int(seqID),
			Data: headerBytes,
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		log.Printf("Failed to marshal ACK message: %v", err)
		return
	}

	s.conn.WriteTo(msgBytes, peer)
}

// 关闭服务器
func (s *Server) Close() error {
	return s.conn.Close()
}

// 主函数
func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage:\n")
		fmt.Printf("  Server mode: %s server [storage_dir]\n", os.Args[0])
		fmt.Printf("  Client mode: %s client <server_ip> <file_path>\n", os.Args[0])
		return
	}

	mode := os.Args[1]

	switch mode {
	case "server":
		storageDir := "./received_files"
		if len(os.Args) > 2 {
			storageDir = os.Args[2]
		}

		server, err := NewServer(storageDir)
		if err != nil {
			log.Fatalf("Failed to create server: %v", err)
		}
		defer server.Close()

		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}

	case "client":
		if len(os.Args) < 4 {
			fmt.Printf("Usage: %s client <server_ip> <file_path>\n", os.Args[0])
			return
		}

		serverIP := os.Args[2]
		filePath := os.Args[3]

		client, err := NewClient(serverIP)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		if err := client.SendFile(filePath); err != nil {
			log.Fatalf("Failed to send file: %v", err)
		}

	default:
		fmt.Printf("Invalid mode: %s\n", mode)
		fmt.Printf("Use 'server' or 'client'\n")
	}
}
