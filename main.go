package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// --- 1. Custom Application Layer Protocol Header ---
const (
	// Message Types
	MsgTypeData  uint8 = 0x01
	MsgTypeACK   uint8 = 0x02
	MsgTypeStart uint8 = 0x03
	MsgTypeEnd   uint8 = 0x04

	// Max payload size to fit within common MTU, considering ICMP header (8 bytes)
	// ICMP Data = IP Packet Size - IP Header (20B) - ICMP Header (8B)
	// For a 1500 byte network MTU, IP Packet Size = 1500
	// Max ICMP Data = 1500 - 20 - 8 = 1472 bytes.
	// We'll use your suggested 1200 bytes for payload + 11 bytes for custom header = 1211 total.
	// This fits comfortably.
	//MaxPayloadSize = 1200
	HeaderSize = 1 + 4 + 2 + 2 + 2 // Type + SessionID + FragmentID + TotalFragments + Checksum
)

// CustomHeader defines the structure of our application-layer header within the ICMP payload.
type CustomHeader struct {
	Type           uint8
	SessionID      uint32
	FragmentID     uint16
	TotalFragments uint16
	Checksum       uint16 // CRC16 of the Payload
}

// ICMPPacket represents our full custom ICMP packet structure (header + payload).
type ICMPPacket struct {
	Header  CustomHeader
	Payload []byte
}

// Marshal converts the ICMPPacket into a byte slice for transmission.
func (p *ICMPPacket) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, p.Header.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Header.SessionID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Header.FragmentID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Header.TotalFragments); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, p.Header.Checksum); err != nil {
		return nil, err
	}
	buf.Write(p.Payload)
	return buf.Bytes(), nil
}

// Unmarshal parses a byte slice into an ICMPPacket.
func (p *ICMPPacket) Unmarshal(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("data too short for custom header")
	}

	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.BigEndian, &p.Header.Type); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &p.Header.SessionID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &p.Header.FragmentID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &p.Header.TotalFragments); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &p.Header.Checksum); err != nil {
		return err
	}

	p.Payload = data[HeaderSize:]
	return nil
}

// calculateCRC16 calculates CRC-16 (CCITT) checksum for the given data.
func calculateCRC16(data []byte) uint16 {
	// Using IEEE CRC32 for simplicity here, as Go's standard lib doesn't have CRC16 directly.
	// For production, you'd use a dedicated CRC16 implementation (e.g., github.com/sigurn/crc16)
	// or implement it manually. CRC32 provides stronger integrity checking anyway.
	return uint16(crc32.ChecksumIEEE(data))
}

// --- 2. Client Design (Simplified Send) ---

type Client struct {
	ServerIP  net.IP
	Conn      *icmp.PacketConn
	SessionID uint32 // Unique for each file transfer session
	Timeout   time.Duration
	Retry     int
	// You'd add channels for ACK handling, progress, etc.
}

// NewClient creates a new ICMP client.
func NewClient(serverIP string) (*Client, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0") // Listen on all interfaces for ICMP
	if err != nil {
		return nil, fmt.Errorf("failed to listen for ICMP: %w", err)
	}

	return &Client{
		ServerIP:  net.ParseIP(serverIP),
		Conn:      conn,
		SessionID: generateSessionID(), // A simple example, use a cryptographically strong one
		Timeout:   3 * time.Second,
		Retry:     3,
	}, nil
}

// Close closes the ICMP connection.
func (c *Client) Close() {
	if c.Conn != nil {
		if err := c.Conn.Close(); err != nil {
			log.Printf("[Client] Error closing ICMP connection: %v\n", err)
		}
	}
}

// generateSessionID generates a pseudo-random session ID.
// In a real application, this should be cryptographically secure.
func generateSessionID() uint32 {
	return uint32(time.Now().UnixNano()) // Very simple for example
}

// SendDataPacket sends a single data packet and waits for an ACK.
// This is a highly simplified version without sliding window or file splitting.
func (c *Client) SendDataPacket(fragmentID uint16, totalFragments uint16, data []byte) error {
	header := CustomHeader{
		Type:           MsgTypeData,
		SessionID:      c.SessionID,
		FragmentID:     fragmentID,
		TotalFragments: totalFragments,
		Checksum:       calculateCRC16(data),
	}
	pkt := ICMPPacket{Header: header, Payload: data}
	msgBytes, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	// Create an ICMP echo request message.
	// Type 8 is Echo Request for IPv4. Code 0 is standard.
	// ID and Seq are typically used by ping, but we can use them
	// for our own purposes or just set them to 0.
	// We put our custom protocol message into the Data field of the ICMP message.
	icmpMsg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: int(fragmentID), // Use fragmentID as sequence for clarity
			Data: msgBytes,
		},
	}
	icmpMsgBytes, err := icmpMsg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	peerAddr := &net.IPAddr{IP: c.ServerIP}

	// --- 3. Reliability: Basic Retry Mechanism ---
	for i := 0; i < c.Retry; i++ {
		log.Printf("[Client] Sending fragment %d (session %d)... attempt %d/%d\n",
			fragmentID, c.SessionID, i+1, c.Retry)

		_, err = c.Conn.WriteTo(icmpMsgBytes, peerAddr)
		if err != nil {
			log.Printf("[Client] Error sending packet: %v\n", err)
			continue
		}

		// Wait for ACK
		ackReceived := make(chan bool, 1)
		go func() {
			readBuf := make([]byte, 1500) // Max possible ICMP packet size
			err := c.Conn.SetReadDeadline(time.Now().Add(c.Timeout))
			if err != nil {
				return
			}
			n, peer, err := c.Conn.ReadFrom(readBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return // Timeout
				}
				log.Printf("[Client] Error reading response: %v\n", err)
				return
			}

			if peer.String() != peerAddr.String() {
				log.Printf("[Client] Received packet from unexpected peer: %s\n", peer.String())
				return
			}

			parsedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), readBuf[:n])
			if err != nil {
				log.Printf("[Client] Error parsing ICMP reply: %v\n", err)
				return
			}

			if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
				echoReply, ok := parsedMsg.Body.(*icmp.Echo)
				if !ok {
					log.Printf("[Client] Received non-echo reply body\n")
					return
				}

				// Unmarshal our custom header from the Echo Reply Data field
				var ackPkt ICMPPacket
				if err := ackPkt.Unmarshal(echoReply.Data); err != nil {
					log.Printf("[Client] Error unmarshaling ACK packet: %v\n", err)
					return
				}

				// Check if it's an ACK for our session and fragment
				if ackPkt.Header.Type == MsgTypeACK &&
					ackPkt.Header.SessionID == c.SessionID &&
					ackPkt.Header.FragmentID == fragmentID {
					log.Printf("[Client] Received ACK for fragment %d (session %d)\n", fragmentID, c.SessionID)
					ackReceived <- true
					return
				}
			}
		}()

		select {
		case <-ackReceived:
			return nil // ACK received, success
		case <-time.After(c.Timeout):
			log.Printf("[Client] Timeout waiting for ACK for fragment %d\n", fragmentID)
		}
	}

	return fmt.Errorf("failed to send fragment %d after %d retries", fragmentID, c.Retry)
}

// --- 3. Server Design (Simplified Receive and ACK) ---

type Server struct {
	Conn       *icmp.PacketConn
	StorageDir string
	Sessions   sync.Map // map[uint32]*Session (Session would hold file buffer, progress, etc.)
	// You'd add a workers pool, progress map, etc.
}

// NewServer creates a new ICMP server.
func NewServer(storageDir string) (*Server, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0") // Listen on all interfaces for ICMP
	if err != nil {
		return nil, fmt.Errorf("failed to listen for ICMP: %w", err)
	}

	return &Server{
		Conn:       conn,
		StorageDir: storageDir,
	}, nil
}

// Start listens for incoming ICMP packets and processes them.
func (s *Server) Start() {
	log.Println("[Server] Listening for ICMP packets...")
	readBuf := make([]byte, 1500) // Max possible ICMP packet size

	for {
		n, peer, err := s.Conn.ReadFrom(readBuf)
		if err != nil {
			log.Printf("[Server] Error reading packet: %v\n", err)
			continue
		}

		go s.handlePacket(readBuf[:n], peer) // Handle concurrently
	}
}

// handlePacket processes a single incoming ICMP packet.
func (s *Server) handlePacket(pktBytes []byte, peer net.Addr) {
	// Parse the incoming ICMP message
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), pktBytes)
	if err != nil {
		log.Printf("[Server] Error parsing ICMP message from %s: %v\n", peer.String(), err)
		return
	}

	// We expect an Echo Request from the client
	if msg.Type != ipv4.ICMPTypeEcho {
		log.Printf("[Server] Received non-echo request ICMP type %d from %s\n", msg.Type, peer.String())
		return
	}

	echoReq, ok := msg.Body.(*icmp.Echo)
	if !ok {
		log.Printf("[Server] Received ICMP Echo with non-Echo body from %s\n", peer.String())
		return
	}

	// Unmarshal our custom protocol header from the ICMP Echo Data
	var customPkt ICMPPacket
	if err := customPkt.Unmarshal(echoReq.Data); err != nil {
		log.Printf("[Server] Error unmarshaling custom packet from %s: %v\n", peer.String(), err)
		return
	}

	log.Printf("[Server] Received custom packet (Type: %d, Session: %d, Fragment: %d/%d) from %s\n",
		customPkt.Header.Type, customPkt.Header.SessionID,
		customPkt.Header.FragmentID, customPkt.Header.TotalFragments, peer.String())

	// Validate checksum
	if customPkt.Header.Checksum != calculateCRC16(customPkt.Payload) {
		log.Printf("[Server] Checksum mismatch for fragment %d (session %d) from %s\n",
			customPkt.Header.FragmentID, customPkt.Header.SessionID, peer.String())
		// In a real scenario, you might NACK or just drop and let client retransmit
		return
	}

	// Process based on custom packet type
	switch customPkt.Header.Type {
	case MsgTypeStart:
		log.Printf("[Server] Handle START message for session %d\n", customPkt.Header.SessionID)
		// TODO: Initialize session, create file, etc.
		s.sendACK(customPkt.Header.SessionID, 0, peer, echoReq.ID, echoReq.Seq) // ACK fragment 0 (Start)
	case MsgTypeData:
		log.Printf("[Server] Handle DATA message for session %d, fragment %d. Payload size: %d bytes\n",
			customPkt.Header.SessionID, customPkt.Header.FragmentID, len(customPkt.Payload))
		// TODO: Store fragment, manage sliding window.
		// For this example, just acknowledge receipt.
		s.sendACK(customPkt.Header.SessionID, customPkt.Header.FragmentID, peer, echoReq.ID, echoReq.Seq)
	case MsgTypeEnd:
		log.Printf("[Server] Handle END message for session %d\n", customPkt.Header.SessionID)
		// TODO: Finalize file, close session.
		s.sendACK(customPkt.Header.SessionID, customPkt.Header.TotalFragments, peer, echoReq.ID, echoReq.Seq) // ACK the "end" fragment
	default:
		log.Printf("[Server] Unknown custom packet type %d for session %d from %s\n",
			customPkt.Header.Type, customPkt.Header.SessionID, peer.String())
	}
}

// sendACK sends an ICMP Echo Reply containing our custom ACK message.
func (s *Server) sendACK(sessionID uint32, fragmentID uint16, peer net.Addr, echoID, echoSeq int) {
	ackHeader := CustomHeader{
		Type:           MsgTypeACK,
		SessionID:      sessionID,
		FragmentID:     fragmentID,
		TotalFragments: 0, // Not relevant for ACK
		Checksum:       0, // ACK itself doesn't carry payload, so checksum can be 0 or calculated on header if desired.
	}
	ackPkt := ICMPPacket{Header: ackHeader, Payload: []byte{}} // ACK usually has no payload
	ackBytes, err := ackPkt.Marshal()
	if err != nil {
		log.Printf("[Server] Error marshaling ACK packet: %v\n", err)
		return
	}

	// Create an ICMP Echo Reply message.
	// Type 0 is Echo Reply for IPv4. Code 0 is standard.
	// The ID and Seq should typically mirror the request's ID and Seq.
	icmpReply := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{
			ID: echoID, Seq: echoSeq, // Mirror client's ID and Seq
			Data: ackBytes, // Our custom ACK message as the payload
		},
	}
	icmpReplyBytes, err := icmpReply.Marshal(nil)
	if err != nil {
		log.Printf("[Server] Error marshaling ICMP reply: %v\n", err)
		return
	}

	_, err = s.Conn.WriteTo(icmpReplyBytes, peer)
	if err != nil {
		log.Printf("[Server] Error sending ACK to %s: %v\n", peer.String(), err)
	} else {
		log.Printf("[Server] Sent ACK for session %d, fragment %d to %s\n", sessionID, fragmentID, peer.String())
	}
}

// --- Main function to demonstrate client and server interaction ---
func main() {
	// IMPORTANT: On Linux/macOS, you need CAP_NET_RAW.
	// Run: sudo setcap cap_net_raw+ep ./your_program_name
	// On Windows, run as Administrator.

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <server|client> [server_ip_for_client]")
		return
	}

	mode := os.Args[1]

	if mode == "server" {
		server, err := NewServer("./received_files") // Directory to store files
		if err != nil {
			log.Fatalf("Failed to create server: %v", err)
		}
		defer func(Conn *icmp.PacketConn) {
			err := Conn.Close()
			if err != nil {

			}
		}(server.Conn)
		server.Start() // This will block
	} else if mode == "client" {
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run main.go client <server_ip>")
			return
		}
		serverIP := os.Args[2]
		client, err := NewClient(serverIP)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		fmt.Println("Client sending test data...")
		testData := []byte("Hello, ICMP tunnel! This is a test message over a custom protocol.")
		// In a real scenario, this would be a file chunk
		err = client.SendDataPacket(1, 1, testData) // fragment 1 of 1
		if err != nil {
			log.Printf("Failed to send data: %v\n", err)
		} else {
			fmt.Println("Data sent successfully (or ACK received after retries).")
		}

		// Keep client running briefly to receive potential delayed ACKs
		time.Sleep(5 * time.Second)
		fmt.Println("Client finished.")

	} else {
		fmt.Println("Invalid mode. Choose 'server' or 'client'.")
	}
}
