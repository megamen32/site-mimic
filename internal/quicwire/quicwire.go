// Package quicwire reads what a QUIC client puts on the wire.
//
// Three things live here, all of them things a server sees before the
// handshake finishes:
//
//   - the ClientHello inside the QUIC Initial packet,
//   - the transport parameters that hello carries,
//   - the HTTP/3 SETTINGS frame of the client's control stream.
//
// The Initial packet is encrypted with keys RFC 9001 derives from the
// client's destination connection id, so a listener can read a client's
// hello without any secret material. That is what makes it possible to
// fingerprint a QUIC client exactly the way the far end sees it, instead
// of trusting what the client says about itself.
package quicwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// v1InitialSalt is the salt RFC 9001 defines for QUIC v1.
var v1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// CryptoFrame is one CRYPTO frame of a QUIC packet: handshake bytes at a
// given offset of the connection's crypto stream.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

// ReadVarint reads a QUIC variable-length integer (RFC 9000 §16) and
// returns its value together with the number of bytes it took.
func ReadVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0]), 1, true
	case 1:
		if len(b) < 2 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<8 | uint64(b[1]), 2, true
	case 2:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[0]&0x3f)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4, true
	default:
		if len(b) < 8 {
			return 0, 0, false
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		return v & 0x3fffffffffffffff, 8, true
	}
}

// Connection is one QUIC connection as a passive listener sees it: the
// connection id its Initial keys came from, and the handshake bytes the
// client sent so far.
//
// A listener cannot keep one key per packet: a client may put a different
// destination connection id in a later Initial packet — the phone's own
// capture shows Google doing exactly that — while RFC 9001 §5.2 keeps the
// keys of the connection's first Initial. The connection id is therefore
// remembered once and used for every packet.
type Connection struct {
	keyDCID []byte
	crypto  map[uint64][]byte
	hello   []byte
}

// NewConnection returns a connection that has seen nothing yet.
func NewConnection() *Connection {
	return &Connection{crypto: map[uint64][]byte{}}
}

// AddInitial decrypts one datagram with this connection's Initial keys and
// adds the handshake bytes it carries.
//
// It reports false for a datagram that is not an Initial of this
// connection, or whose header protection did not come off. A listener
// treats that as "not mine" and keeps reading.
func (c *Connection) AddInitial(datagram []byte) bool {
	dcid, ok := DestinationConnectionID(datagram)
	if !ok {
		return false
	}
	if c.keyDCID == nil {
		// A copy: the connection id is a slice of the caller's buffer, and
		// a socket buffer is reused for the next datagram.
		c.keyDCID = append([]byte(nil), dcid...)
	}
	frames, ok := InitialCryptoFrames(datagram, c.keyDCID)
	if !ok {
		return false
	}
	for _, frame := range frames {
		c.crypto[frame.Offset] = frame.Data
	}
	if msg, ok := ClientHelloMessage(c.crypto); ok {
		c.hello = msg
	}
	return true
}

// KeyDCID returns the destination connection id the Initial keys were
// derived from — the one of the connection's first Initial packet.
func (c *Connection) KeyDCID() []byte {
	return c.keyDCID
}

// ClientHello returns the ClientHello the client sent, once the handshake
// bytes it carries are complete.
func (c *Connection) ClientHello() ([]byte, bool) {
	return c.hello, c.hello != nil
}

// DestinationConnectionID returns the destination connection id of a QUIC
// packet. The slice points into the datagram: copy it before keeping it.
func DestinationConnectionID(datagram []byte) ([]byte, bool) {
	dcid, _, _, ok := parseLongHeader(datagram)
	if !ok {
		return nil, false
	}
	return dcid, true
}

// InitialCryptoFrames decrypts a QUIC Initial packet with the Initial keys
// derived from dcid, and returns its CRYPTO frames.
//
// The dcid is the destination connection id of the connection's FIRST
// Initial packet, not necessarily the one in this packet: the keys do not
// change when the connection id does.
//
// It reports false for anything that is not a decryptable Initial: a
// short packet, a Handshake packet, a packet whose header protection did
// not come off.
func InitialCryptoFrames(datagram, dcid []byte) ([]CryptoFrame, bool) {
	_, header, pnAndPayload, ok := parseLongHeader(datagram)
	if !ok {
		return nil, false
	}
	secret, err := hkdf.Extract(sha256.New, dcid, v1InitialSalt)
	if err != nil {
		return nil, false
	}
	clientSecret, err := hkdf.Expand(sha256.New, secret, string(expandLabel("client in", 32)), 32)
	if err != nil {
		return nil, false
	}
	key, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic key", 16)), 16)
	if err != nil {
		return nil, false
	}
	iv, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic iv", 12)), 12)
	if err != nil {
		return nil, false
	}
	hp, err := hkdf.Expand(sha256.New, clientSecret, string(expandLabel("quic hp", 16)), 16)
	if err != nil {
		return nil, false
	}
	payload, ok := decryptInitialPayload(header, pnAndPayload, key, iv, hp)
	if !ok {
		return nil, false
	}
	return cryptoFrames(payload), true
}

// ClientHelloMessage assembles CRYPTO frames into the TLS handshake stream
// and returns the ClientHello when it is complete.
//
// The returned bytes are a TLS handshake message with its four-byte header
// (type 1, three-byte length) and nothing else — QUIC carries handshake
// messages without TLS records, but the bytes inside are the same.
func ClientHelloMessage(frames map[uint64][]byte) ([]byte, bool) {
	size := uint64(0)
	for offset, data := range frames {
		if offset+uint64(len(data)) > size {
			size = offset + uint64(len(data))
		}
	}
	if size < 4 {
		return nil, false
	}
	stream := make([]byte, size)
	for offset, data := range frames {
		copy(stream[offset:], data)
	}
	length := uint64(stream[1])<<16 | uint64(stream[2])<<8 | uint64(stream[3])
	if uint64(len(stream)) < 4+length {
		return nil, false
	}
	return stream[:4+length], true
}

// TransportParameters reads a marshalled transport parameter list
// (RFC 9000 §18) into id -> value pairs.
func TransportParameters(raw []byte) (map[uint64][]byte, error) {
	out := map[uint64][]byte{}
	for pos := 0; pos < len(raw); {
		id, n, ok := ReadVarint(raw[pos:])
		if !ok {
			return nil, fmt.Errorf("quicwire: truncated parameter id at %d", pos)
		}
		pos += n
		length, n, ok := ReadVarint(raw[pos:])
		if !ok {
			return nil, fmt.Errorf("quicwire: truncated parameter length at %d", pos)
		}
		pos += n
		if pos+int(length) > len(raw) {
			return nil, fmt.Errorf("quicwire: parameter 0x%02x claims %d bytes, only %d left",
				id, length, len(raw)-pos)
		}
		out[id] = raw[pos : pos+int(length)]
		pos += int(length)
	}
	return out, nil
}

// IsGREASEParamID reports whether a transport parameter id belongs to the
// GREASE family RFC 9000 reserves (0x1b..0x3a, every 31st value).
func IsGREASEParamID(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}

// H3Settings decodes the SETTINGS frame at the head of an HTTP/3 control
// stream and reports whether the frame is complete.
//
// The control stream stays open for the life of the connection, so the
// bytes arrive in pieces: the caller keeps the buffer and calls this again
// until it says the frame is complete.
func H3Settings(raw []byte) (map[uint64]uint64, bool) {
	settings := map[uint64]uint64{}
	if len(raw) == 0 {
		return settings, false
	}
	streamType, pos, ok := ReadVarint(raw)
	if !ok || streamType != 0x00 {
		return settings, false
	}
	frameType, n, ok := ReadVarint(raw[pos:])
	if !ok {
		return settings, false
	}
	pos += n
	if frameType != 0x04 {
		return settings, false
	}
	length, n, ok := ReadVarint(raw[pos:])
	if !ok {
		return settings, false
	}
	pos += n
	if pos+int(length) > len(raw) {
		return settings, false
	}
	payload := raw[pos : pos+int(length)]
	for len(payload) > 0 {
		id, n, ok := ReadVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		value, n, ok := ReadVarint(payload)
		if !ok {
			return settings, false
		}
		payload = payload[n:]
		settings[id] = value
	}
	return settings, true
}

// expandLabel builds the HKDF-ExpandLabel info of TLS 1.3 (RFC 8446 §7.1).
func expandLabel(label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return info
}

// parseLongHeader returns the destination connection id, the header bytes
// without the packet number, and the packet number with the payload.
func parseLongHeader(datagram []byte) ([]byte, []byte, []byte, bool) {
	if len(datagram) < 6 || datagram[0]&0x80 == 0 {
		return nil, nil, nil, false
	}
	if (datagram[0]&0x30)>>4 != 0 {
		return nil, nil, nil, false // not an Initial
	}
	pos := 5
	dcidLen := int(datagram[pos])
	pos++
	if pos+dcidLen > len(datagram) {
		return nil, nil, nil, false
	}
	dcid := datagram[pos : pos+dcidLen]
	pos += dcidLen
	scidLen := int(datagram[pos])
	pos++
	if pos+scidLen > len(datagram) {
		return nil, nil, nil, false
	}
	pos += scidLen
	tokenLen, n, ok := ReadVarint(datagram[pos:])
	if !ok {
		return nil, nil, nil, false
	}
	pos += n + int(tokenLen)
	length, n, ok := ReadVarint(datagram[pos:])
	if !ok {
		return nil, nil, nil, false
	}
	pos += n
	if pos+int(length) > len(datagram) {
		return nil, nil, nil, false
	}
	return dcid, datagram[:pos], datagram[pos : pos+int(length)], true
}

// decryptInitialPayload removes the header protection and decrypts the
// payload of a QUIC Initial packet.
func decryptInitialPayload(header, pnAndPayload, key, iv, hp []byte) ([]byte, bool) {
	if len(pnAndPayload) < 4+16+16 {
		return nil, false
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	sample := pnAndPayload[4:20]
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	first := header[0] ^ (mask[0] & 0x0f)
	if (first&0x30)>>4 != 0 {
		return nil, false
	}
	pnLen := int(first&0x03) + 1
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = pnAndPayload[i] ^ mask[1+i]
	}
	pn := uint64(0)
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	fullHeader := append([]byte{first}, header[1:]...)
	fullHeader = append(fullHeader, pnBytes...)

	gcm, err := cipher.NewGCM(blockForKey(key))
	if err != nil {
		return nil, false
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := gcm.Open(nil, nonce, pnAndPayload[pnLen:], fullHeader)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// blockForKey returns an AES block cipher for the given key.
func blockForKey(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	return block
}

// cryptoFrames returns the CRYPTO frames of a decrypted QUIC payload.
//
// A CRYPTO frame carries its offset before its length (RFC 9000 §19.6), and
// both are variable-length integers.
func cryptoFrames(payload []byte) []CryptoFrame {
	var frames []CryptoFrame
	pos := 0
	for pos < len(payload) {
		frameType, n, ok := ReadVarint(payload[pos:])
		if !ok {
			return frames
		}
		pos += n
		if frameType == 0x00 || frameType == 0x01 {
			// PADDING and PING carry no length and no payload.
			continue
		}
		if frameType == 0x06 {
			offset, offsetLen, ok := ReadVarint(payload[pos:])
			if !ok {
				return frames
			}
			pos += offsetLen
			length, lengthLen, ok := ReadVarint(payload[pos:])
			if !ok {
				return frames
			}
			pos += lengthLen
			if pos+int(length) > len(payload) {
				return frames
			}
			frames = append(frames, CryptoFrame{
				Offset: offset,
				Data:   append([]byte(nil), payload[pos:pos+int(length)]...),
			})
			pos += int(length)
			continue
		}
		length, n, ok := ReadVarint(payload[pos:])
		if !ok {
			return frames
		}
		pos += n
		if pos+int(length) > len(payload) {
			return frames
		}
		pos += int(length)
	}
	return frames
}

// ErrNoClientHello is returned when a connection carried no ClientHello.
var ErrNoClientHello = errors.New("quicwire: no ClientHello in the Initial packets")
