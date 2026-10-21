package quicwire_test

import (
	"encoding/binary"

	"os"
	"testing"

	"github.com/megamen32/site-mimic/internal/quicwire"
	"github.com/megamen32/site-mimic/mimic"
)

// TestReadVarint checks the four encodings of a QUIC variable-length
// integer (RFC 9000 §16): the length is in the two high bits of the first
// byte, and a one-byte value must not be read as two.
func TestReadVarint(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		value uint64
		size  int
	}{
		{"one byte", []byte{0x25}, 37, 1},
		{"two bytes", []byte{0x7b, 0xbd}, 15293, 2},
		{"four bytes", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4},
		{"eight bytes", []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8},
		{"zero", []byte{0x00}, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n, ok := quicwire.ReadVarint(tc.bytes)
			if !ok {
				t.Fatal("the varint did not parse")
			}
			if got != tc.value {
				t.Errorf("value = %d, want %d", got, tc.value)
			}
			if n != tc.size {
				t.Errorf("read %d bytes, want %d", n, tc.size)
			}
		})
	}
}

// TestReadVarintRejectsTruncatedInput checks that a varint cut short is
// refused instead of read from the bytes that are there.
func TestReadVarintRejectsTruncatedInput(t *testing.T) {
	for _, b := range [][]byte{{}, {0x40}, {0x80, 0x00}, {0xc0, 0x00, 0x00}} {
		if _, _, ok := quicwire.ReadVarint(b); ok {
			t.Errorf("the truncated varint %x parsed", b)
		}
	}
}

// TestARealChromeHelloOnTheWire decrypts the QUIC Initial packets a real
// Chrome sent and reads the ClientHello out of them.
//
// The fixture is the phone's own capture (2026-08-30, Chrome on the S21,
// a QUIC handshake to a Google server): three Initial packets, taken from
// the wire as they were. Nothing in it is a copy of this library's own
// output, so the test fails if the decryption, the CRYPTO reassembly or
// the hello parsing is wrong.
func TestARealChromeHelloOnTheWire(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome_quic_initial.datagrams")
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	conn := quicwire.NewConnection()
	packets := 0
	for pos := 0; pos+4 <= len(raw); {
		n := binary.BigEndian.Uint32(raw[pos:])
		pos += 4
		if pos+int(n) > len(raw) {
			t.Fatalf("the fixture claims %d bytes at %d, only %d left", n, pos, len(raw)-pos)
		}
		conn.AddInitial(raw[pos : pos+int(n)])
		pos += int(n)
		packets++
	}
	if packets != 3 {
		t.Fatalf("the fixture holds %d Initial packets, want 3", packets)
	}

	msg, ok := conn.ClientHello()
	if !ok {
		t.Fatal("the CRYPTO frames did not assemble into a hello")
	}
	hello, err := mimic.ParseClientHello(helloRecord(msg))
	if err != nil {
		t.Fatalf("parse the hello: %v", err)
	}

	// The fingerprint of that hello, measured on the phone's wire.
	if got, want := hello.JA4QUIC(), "q13d0311h3_55b375c5d22e_653d80c3fe9d"; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
	if got, want := hello.SNI, "www.google.com"; got != want {
		t.Errorf("SNI = %q, want %q", got, want)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v, want [h3]", hello.ALPN)
	}
	if got, want := len(hello.Extensions), 11; got != want {
		t.Errorf("%d extensions, want %d", got, want)
	}
	if got, want := len(hello.CipherSuites), 3; got != want {
		t.Errorf("%d cipher suites, want %d", got, want)
	}

	// The transport parameters the same hello carried.
	tp, err := quicwire.TransportParameters(hello.ExtensionData[0x39])
	if err != nil {
		t.Fatalf("the transport parameters: %v", err)
	}
	if got, want := string(tp[0x3128]), "ORIGECCPIW2X"; got != want {
		t.Errorf("google_connection_options = %q, want %q", got, want)
	}
	// The GREASE parameter of that capture: a random id and a random value.
	var greaseID uint64
	var greaseValue []byte
	for id, value := range tp {
		if quicwire.IsGREASEParamID(id) {
			greaseID, greaseValue = id, value
		}
	}
	if greaseID == 0 {
		t.Error("the parameters carry no GREASE parameter")
	}
	if len(greaseValue) > 15 {
		t.Errorf("the GREASE parameter carries %d bytes, want at most 15", len(greaseValue))
	}
}

// TestTheKeysSurviveAConnectionIDChange checks the rule of RFC 9001 §5.2
// against the capture: the client's third Initial packet carries a
// different destination connection id than its first one, and it is still
// encrypted with the keys of the first.
//
// A sniffer that derived the keys from each packet's own connection id
// would drop that packet — and with it the last third of the hello.
func TestTheKeysSurviveAConnectionIDChange(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome_quic_initial.datagrams")
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	var packets [][]byte
	for pos := 0; pos+4 <= len(raw); {
		n := binary.BigEndian.Uint32(raw[pos:])
		pos += 4
		packets = append(packets, raw[pos:pos+int(n)])
		pos += int(n)
	}
	if len(packets) != 3 {
		t.Fatalf("the fixture holds %d packets, want 3", len(packets))
	}

	first, ok := quicwire.DestinationConnectionID(packets[0])
	if !ok {
		t.Fatal("the first packet has no destination connection id")
	}
	third, ok := quicwire.DestinationConnectionID(packets[2])
	if !ok {
		t.Fatal("the third packet has no destination connection id")
	}
	if string(first) == string(third) {
		t.Skip("this capture does not change the connection id")
	}

	// The keys of the third packet are the ones of the first.
	if _, ok := quicwire.InitialCryptoFrames(packets[2], first); !ok {
		t.Error("the third packet did not decrypt with the keys of the first")
	}
	// The keys of the third packet are not the ones of its own id.
	if _, ok := quicwire.InitialCryptoFrames(packets[2], third); ok {
		t.Error("the third packet decrypted with the keys of its own connection id")
	}

	// The connection keeps them: all three packets land in one hello.
	conn := quicwire.NewConnection()
	for _, packet := range packets {
		conn.AddInitial(packet)
	}
	if _, ok := conn.ClientHello(); !ok {
		t.Error("the three packets did not assemble into a hello")
	}
	if string(conn.KeyDCID()) != string(first) {
		t.Errorf("the connection kept the id %x, want the first one %x", conn.KeyDCID(), first)
	}
}

// TestTheCapturedHelloHasAnEmptySourceConnectionID checks the connection id
// Chrome puts on the wire: it sends none of its own.
//
// The source connection id is in the long header, not in the hello, so this
// is a property of the packets the fixture holds.
func TestTheCapturedHelloHasAnEmptySourceConnectionID(t *testing.T) {
	raw, err := os.ReadFile("testdata/chrome_quic_initial.datagrams")
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	for pos := 0; pos+4 <= len(raw); {
		n := binary.BigEndian.Uint32(raw[pos:])
		pos += 4
		packet := raw[pos : pos+int(n)]
		pos += int(n)
		if len(packet) < 7 {
			t.Fatalf("a packet holds %d bytes", len(packet))
		}
		dcidLen := int(packet[5])
		scidLenPos := 6 + dcidLen
		if scidLenPos >= len(packet) {
			t.Fatal("the packet is shorter than its connection ids")
		}
		if got := packet[scidLenPos]; got != 0 {
			t.Errorf("the source connection id is %d bytes, want 0", got)
		}
	}
}

// TestTransportParametersRejectsTruncatedInput checks that a parameter list
// cut short is refused instead of read past its end.
func TestTransportParametersRejectsTruncatedInput(t *testing.T) {
	if _, err := quicwire.TransportParameters([]byte{0x01, 0x10, 0x00}); err == nil {
		t.Error("a truncated parameter list parsed")
	}
}

// TestH3Settings reads a control stream's SETTINGS frame.
//
// The frame is the one Chrome sends: QPACK table capacity, field section
// size, blocked streams, datagrams and a GREASE setting with a random id.
// The values are varints, so 65536 takes four bytes and 100 takes two:
// 0x64 on its own would start a two-byte varint and read the next byte
// into the value.
func TestH3Settings(t *testing.T) {
	raw := h3ControlStream()
	settings, ok := quicwire.H3Settings(raw)
	if !ok {
		t.Fatal("the SETTINGS frame did not decode")
	}
	want := map[uint64]uint64{0x01: 65536, 0x06: 262144, 0x07: 100, 0x33: 1, 0x24: 7}
	if len(settings) != len(want) {
		t.Fatalf("%d settings, want %d (%v)", len(settings), len(want), settings)
	}
	for id, wantValue := range want {
		if got := settings[id]; got != wantValue {
			t.Errorf("setting 0x%02x = %d, want %d", id, got, wantValue)
		}
	}
}

// TestH3SettingsWaitsForTheWholeFrame checks that a control stream read in
// pieces is not mistaken for a complete frame: the control stream stays
// open for the life of the connection, so the bytes arrive in parts.
func TestH3SettingsWaitsForTheWholeFrame(t *testing.T) {
	full := h3ControlStream()
	for cut := 1; cut < len(full); cut++ {
		if _, ok := quicwire.H3Settings(full[:cut]); ok {
			t.Errorf("a %d-byte prefix was taken for a whole frame", cut)
		}
	}
	if _, ok := quicwire.H3Settings(full); !ok {
		t.Error("the whole frame did not decode")
	}
}

// h3ControlStream is the head of an HTTP/3 control stream with the
// settings Chrome sends.
func h3ControlStream() []byte {
	return []byte{
		0x00,       // stream type: control
		0x04, 0x11, // frame type SETTINGS, length 17
		0x01, 0x80, 0x01, 0x00, 0x00, // 0x01 = 65536
		0x06, 0x80, 0x04, 0x00, 0x00, // 0x06 = 262144
		0x07, 0x40, 0x64, // 0x07 = 100 (two bytes: 0x64 alone would be a two-byte varint)
		0x33, 0x01, // 0x33 = 1
		0x24, 0x07, // 0x24 = 7 (a GREASE setting)
	}
}

// helloRecord wraps a TLS handshake message in a record header, so the
// library's ClientHello parser can read it — QUIC carries handshake
// messages without records, but the bytes inside are the same.
func helloRecord(msg []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}
