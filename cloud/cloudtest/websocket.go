package cloudtest

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// A minimal WebSocket server (RFC 6455) for the fake guest services: it echoes every frame
// back (text, binary, continuation frames with their FIN bit), answers pings, and echoes a
// close. The SDK has no dependencies, so this is written out here.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// IsWebSocketUpgrade reports whether r asks for a WebSocket upgrade.
func IsWebSocketUpgrade(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// WebSocketAccept is the Sec-WebSocket-Accept value for a Sec-WebSocket-Key.
func WebSocketAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// serveWebSocketEcho completes the handshake (choosing the first subprotocol the client
// offers) and echoes frames until the client closes or the connection ends.
func serveWebSocketEcho(w http.ResponseWriter, r *http.Request) { serveWebSocket(w, r, nil, nil) }

// serveWebSocket is serveWebSocketEcho with an optional first-message check (auth: the first
// client frame must be a text message it accepts, within 5 s, else the connection closes, as
// agent-companion's terminal WebSocket does) and a callback when the connection ends.
func serveWebSocket(w http.ResponseWriter, r *http.Request, auth func(payload []byte) bool, onClose func()) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "bad websocket handshake", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if onClose != nil {
		defer onClose()
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + WebSocketAccept(key) + "\r\n"
	if p := r.Header.Get("Sec-WebSocket-Protocol"); p != "" {
		resp += "Sec-WebSocket-Protocol: " + strings.TrimSpace(strings.Split(p, ",")[0]) + "\r\n"
	}
	if _, err := rw.WriteString(resp + "\r\n"); err != nil || rw.Flush() != nil {
		return
	}
	if auth != nil {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		fin, op, payload, err := ReadWebSocketFrame(rw.Reader)
		if err != nil || !fin || op != 0x1 || !auth(payload) {
			_ = WriteWebSocketFrame(conn, true, 0x1, []byte("Auth timeout or invalid payload"), false)
			_ = WriteWebSocketFrame(conn, true, 0x8, []byte{0x03, 0xf0}, false) // 1008 policy violation
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
	}
	for {
		fin, op, payload, err := ReadWebSocketFrame(rw.Reader)
		if err != nil {
			return
		}
		switch op {
		case 0x8: // close: echo it and stop
			_ = WriteWebSocketFrame(conn, true, 0x8, payload, false)
			return
		case 0x9: // ping
			if WriteWebSocketFrame(conn, true, 0xA, payload, false) != nil {
				return
			}
		case 0xA: // pong
		default:
			if WriteWebSocketFrame(conn, fin, op, payload, false) != nil {
				return
			}
		}
	}
}

// ReadWebSocketFrame reads one frame (unmasking it when masked).
func ReadWebSocketFrame(r *bufio.Reader) (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	fin, op = h[0]&0x80 != 0, h[0]&0x0f
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 16<<20 {
		return false, 0, nil, errors.New("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, op, payload, nil
}

// WriteWebSocketFrame writes one frame; clients mask (mask true), servers do not.
func WriteWebSocketFrame(w io.Writer, fin bool, op byte, payload []byte, mask bool) error {
	b := []byte{op}
	if fin {
		b[0] |= 0x80
	}
	var m byte
	if mask {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, m|byte(n))
	case n <= 0xffff:
		b = append(b, m|126, byte(n>>8), byte(n))
	default:
		b = append(b, m|127)
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	body := payload
	if mask {
		key := []byte(randHex(2)) // 4 bytes
		b = append(b, key...)
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i%4]
		}
	}
	_, err := w.Write(append(b, body...))
	return err
}
