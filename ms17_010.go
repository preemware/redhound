package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// -----------------------------------------------------------------------------
// MS17-010 (EternalBlue) vulnerability scanner utilities
// Based on the public proof-of-concept by Ch4meleon, ported to fit redhound.
// Only minimal SMB1 conversation required to elicit the STATUS_INSUFF_SERVER_RESOURCES
// response (0xC0000205) that indicates the host is vulnerable.
// -----------------------------------------------------------------------------

const (
	smbHeaderLen        = 32
	netbiosHeaderLen    = 4
	statusInSuffRsrcs   = 0xC0000205 // NT_STATUS: STATUS_INSUFF_SERVER_RESOURCES (vulnerable)
	statusAccessDenied  = 0xC0000022 // NT_STATUS: STATUS_ACCESS_DENIED (patched)
	statusInvalidHandle = 0xC0000008 // NT_STATUS: STATUS_INVALID_HANDLE (patched)
)

// smb1Header represents the first 32 bytes of an SMB1 packet header (little-endian).
type smb1Header struct {
	ServerComponent uint32 // 0xFF 'SMB'
	SmbCommand      uint8
	NTStatus        uint32 // NT_STATUS field (replaces ErrorClass/Reserved1/ErrorCode)
	Flags           uint8
	Flags2          uint16
	ProcessIDHigh   uint16
	Signature       uint64
	Reserved2       uint16
	TreeID          uint16
	ProcessID       uint16
	UserID          uint16
	MultiplexID     uint16
}

func parseSMB1Header(b []byte) (*smb1Header, error) {
	if len(b) < smbHeaderLen {
		return nil, errors.New("buffer too small for SMB header")
	}
	var h smb1Header
	if err := binary.Read(bytes.NewReader(b[:smbHeaderLen]), binary.LittleEndian, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// netbiosHdr builds the 4-byte NetBIOS Session Service header for the given payload length.
func netbiosHdr(payloadLen int) []byte {
	// 0x00 session message, then 3-byte BE length
	h := []byte{0x00, 0x00, 0x00, 0x00}
	h[1] = byte((payloadLen >> 16) & 0xFF)
	h[2] = byte((payloadLen >> 8) & 0xFF)
	h[3] = byte(payloadLen & 0xFF)
	return h
}

// join concatenates byte slices efficiently.
func join(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// --- Packet builders ---------------------------------------------------------

func negotiateProtoRequest() []byte {
	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42, // .SMB
		0x72,                   // Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // NT status
		0x18,       // flags
		0x01, 0x28, // flags2
		0x00, 0x00, // PID High
		// signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // reserved2
		0x00, 0x00, // tree id
		0x2F, 0x4B, // process id
		0x00, 0x00, // user id
		0xC5, 0x5E, // multiplex id
	}

	payload := []byte{
		0x00,       // WordCount
		0x31, 0x00, // ByteCount
		// dialects
		0x02, 'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', 0x00,
		0x02, 'L', 'M', '1', '.', '2', 'X', '0', '0', '2', 0x00,
		0x02, 'N', 'T', ' ', 'L', 'A', 'N', 'M', 'A', 'N', ' ', '1', '.', '0', 0x00,
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
	}

	pdu := join(smbHeader, payload)
	return join(netbiosHdr(len(pdu)), pdu)
}

func sessionSetupAndxRequest() []byte {
	smbHeader := []byte{
		0xFF, 0x53, 0x4D, 0x42,
		0x73, // Session Setup AndX
		0x00, 0x00, 0x00, 0x00,
		0x18,
		0x01, 0x20,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x2F, 0x4B,
		0x00, 0x00,
		0xC5, 0x5E,
	}

	payload := []byte{
		0x0D,
		0xFF, 0x00,
		0x00, 0x00,
		0xDF, 0xFF,
		0x02, 0x00,
		0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00,
		0x26, 0x00,
		0x00,
		0x2E, 0x00,
		'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', '2', '0', '0', '0', ' ', '2', '1', '9', '5', 0x00,
		'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', '2', '0', '0', '0', ' ', '5', '.', '0', 0x00,
	}

	pdu := join(smbHeader, payload)
	return join(netbiosHdr(len(pdu)), pdu)
}

// fixed: correct ByteCount placement/calculation in Tree Connect AndX
func treeConnectAndxRequest(ip string, userID uint16) []byte {
	/* SMB header (unchanged) */
	header := []byte{
		0xFF, 0x53, 0x4D, 0x42, // "SMB"
		0x75,                   // Tree Connect AndX
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x18,       // Flags
		0x01, 0x20, // Flags2
		0x00, 0x00, // PID-High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
		0x00, 0x00, // reserved2
		0x00, 0x00, // TreeID (filled below)
		0x2F, 0x4B, // ProcessID
		0x00, 0x00, // UserID (filled below)
		0xC5, 0x5E, // MultiplexID
	}
	binary.LittleEndian.PutUint16(header[28:], userID) // fill UserID

	/* SMB parameters */
	wordParams := []byte{
		0x04,       // WordCount (4 words = 8 bytes follow)
		0xFF, 0x00, // AndXCommand = no further AndX, Reserved
		0x00, 0x00, // AndXOffset (will be ignored by most servers)
		0x00, 0x00, // Flags
		0x01, 0x00, // PasswordLength = 1 (null)
	}

	// build the variable-length section
	pipePath := fmt.Sprintf("\\\\%s\\IPC$", ip)
	var payload bytes.Buffer
	payload.Write(wordParams)
	payload.Write([]byte{0x00, 0x00}) // ByteCount placeholder
	payload.WriteByte(0x00)           // Password (null)
	payload.Write(append([]byte(pipePath), 0x00))
	payload.Write([]byte{0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x00}) // service "?????"
	payload.Write([]byte("_TREEPATH_REPLACE__????\x00"))      // padding (unchanged)

	// calculate the correct ByteCount and write it back *at the right spot*
	byteCount := uint16(payload.Len() - (len(wordParams) + 2)) // after ByteCount itself
	binary.LittleEndian.PutUint16(payload.Bytes()[len(wordParams):], byteCount)

	pdu := append(header, payload.Bytes()...)
	return append(netbiosHdr(len(pdu)), pdu...)
}

func peekNamedPipeRequest(treeID, processID, userID, multiplexID uint16) []byte {
	header := []byte{
		0xFF, 0x53, 0x4D, 0x42, // SMB signature
		0x25,                   // SMB_COM_TRANSACTION
		0x00, 0x00, 0x00, 0x00, // NT Status
		0x18,       // Flags
		0x01, 0x28, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved2
		0x00, 0x00, // TreeID (filled below)
		0x00, 0x00, // ProcessID (filled below)
		0x00, 0x00, // UserID (filled below)
		0x00, 0x00, // MultiplexID (filled below)
	}
	binary.LittleEndian.PutUint16(header[24:], treeID)
	binary.LittleEndian.PutUint16(header[26:], processID)
	binary.LittleEndian.PutUint16(header[28:], userID)
	binary.LittleEndian.PutUint16(header[30:], multiplexID)

	// SMB_COM_TRANSACTION parameters (matching Nmap implementation)
	payload := []byte{
		0x10,       // WordCount (16 words = 32 bytes of parameters)
		0x00, 0x00, // Total Parameter count
		0x00, 0x00, // Total Data count
		0xFF, 0xFF, // Max Parameter count
		0xFF, 0xFF, // Max Data count
		0x00,       // Max setup Count
		0x00,       // Reserved
		0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Timeout
		0x00, 0x00, // Reserved
		0x00, 0x00, // ParameterCount
		0x4A, 0x00, // ParameterOffset (little-endian)
		0x00, 0x00, // DataCount
		0x4A, 0x00, // DataOffset (little-endian)
		0x02,       // SetupCount (2 setup words)
		0x00,       // Reserved
		0x23, 0x00, // PeekNamedPipe opcode (little-endian)
		0x00, 0x00, // Second setup word
		0x07, 0x00, // ByteCount (length of "\PIPE\")
		// Data: "\PIPE\"
		'\\', 'P', 'I', 'P', 'E', '\\', 0x00,
	}

	pdu := join(header, payload)
	return join(netbiosHdr(len(pdu)), pdu)
}

// sendRecvMS17 writes a request and optionally reads a response into buf.
// If buf is nil, the response is discarded.
func sendRecvMS17(conn net.Conn, req []byte, buf []byte) error {
	if _, err := conn.Write(req); err != nil {
		return err
	}
	if buf == nil {
		return nil
	}
	// Read NetBIOS header first
	if _, err := io.ReadFull(conn, buf[:netbiosHeaderLen]); err != nil {
		return err
	}
	payloadLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if payloadLen+netbiosHeaderLen > len(buf) {
		payloadLen = len(buf) - netbiosHeaderLen
	}
	if _, err := io.ReadFull(conn, buf[netbiosHeaderLen:netbiosHeaderLen+payloadLen]); err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	return nil
}

// checkMS17_010 returns true if the target appears vulnerable to MS17-010.
func checkMS17_010(dialer proxy.Dialer, ip string, port uint16, timeout time.Duration) (bool, error) {
	address := fmt.Sprintf("%s:%d", ip, port)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var conn net.Conn
	var err error

	if netDialer, ok := dialer.(*net.Dialer); ok {
		conn, err = netDialer.DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return false, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var buf [1024]byte

	// 1. Negotiate Protocol - must read response for MS17-010 to work properly
	if err := sendRecvMS17(conn, negotiateProtoRequest(), buf[:]); err != nil {
		return false, fmt.Errorf("negotiate protocol failed: %w", err)
	}

	// 2. Session Setup AndX
	if err := sendRecvMS17(conn, sessionSetupAndxRequest(), buf[:]); err != nil {
		return false, fmt.Errorf("session setup failed: %w", err)
	}
	hdr, err := parseSMB1Header(buf[netbiosHeaderLen : netbiosHeaderLen+smbHeaderLen])
	if err != nil {
		return false, fmt.Errorf("parsing session setup response: %w", err)
	}
	userID := hdr.UserID

	// 3. Tree Connect AndX
	if err := sendRecvMS17(conn, treeConnectAndxRequest(ip, userID), buf[:]); err != nil {
		return false, fmt.Errorf("tree connect failed: %w", err)
	}
	hdrTC, err := parseSMB1Header(buf[netbiosHeaderLen : netbiosHeaderLen+smbHeaderLen])
	if err != nil {
		return false, fmt.Errorf("parsing tree connect response: %w", err)
	}

	// 4. PeekNamedPipe - this is the key request that triggers the vulnerability
	if err := sendRecvMS17(conn, peekNamedPipeRequest(hdrTC.TreeID, hdrTC.ProcessID, hdrTC.UserID, hdrTC.MultiplexID), buf[:]); err != nil {
		return false, fmt.Errorf("peek named pipe failed: %w", err)
	}
	hdrPeek, err := parseSMB1Header(buf[netbiosHeaderLen : netbiosHeaderLen+smbHeaderLen])
	if err != nil {
		return false, fmt.Errorf("parsing peek named pipe response: %w", err)
	}

	// Check if the NT_STATUS indicates MS17-010 vulnerability
	// STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) indicates vulnerability
	if hdrPeek.NTStatus == statusInSuffRsrcs {
		return true, nil
	}

	// Check for known patched system responses
	switch hdrPeek.NTStatus {
	case statusAccessDenied: // STATUS_ACCESS_DENIED - system is likely patched
		return false, fmt.Errorf("system appears to be patched (STATUS_ACCESS_DENIED)")
	case statusInvalidHandle: // STATUS_INVALID_HANDLE - system is likely patched
		return false, fmt.Errorf("system appears to be patched (STATUS_INVALID_HANDLE)")
	default:
		return false, fmt.Errorf("unexpected NT_STATUS response: 0x%08X", hdrPeek.NTStatus)
	}
}
