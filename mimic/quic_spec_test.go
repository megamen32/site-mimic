package mimic

import (
	"encoding/hex"
	"testing"
)

// helloRecord wraps a TLS handshake message in a record header, so the
// library's ClientHello parser can read it — QUIC carries handshake messages
// without records, but the bytes inside are the same.
func helloRecord(msg []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}

// TestChromeH3Settings pins the HTTP/3 settings to the values a real
// browser sent.
//
// The expected values are written out as literals, not as references to the
// implementation's constants: a test that compares the implementation with a
// copy of its own constants passes whatever both say. Here a changed value
// breaks the test.
//
// Measured on the wire (2026-10-21, Google Chrome 155 on macOS, HTTP/3
// against a local server that printed the client's control stream).
func TestChromeH3Settings(t *testing.T) {
	settings := chromeH3Settings()
	want := map[uint64]uint64{
		0x01: 65536,  // QPACK_MAX_TABLE_CAPACITY
		0x06: 262144, // MAX_FIELD_SECTION_SIZE
		0x07: 100,    // QPACK_BLOCKED_STREAMS
		0x33: 1,      // H3_DATAGRAM
	}
	if len(settings) != len(want) {
		t.Errorf("%d settings, want %d (%v)", len(settings), len(want), settings)
	}
	for id, wantValue := range want {
		got, ok := settings[id]
		if !ok {
			t.Errorf("setting 0x%02x missing", id)
			continue
		}
		if got != wantValue {
			t.Errorf("setting 0x%02x = %d, want %d", id, got, wantValue)
		}
	}
}

// TestChromeQUICGoogleConnectionOptions pins the google_connection_options
// value: the captured token, not the shorter one the QUIC stack ships.
func TestChromeQUICGoogleConnectionOptions(t *testing.T) {
	_, quicConfig := chromeQUICConfig(transportOptions{}, "chrome_156")
	got, ok := quicConfig.AdditionalTransportParameters[quicChromeGoogleConnOptionsID]
	if !ok {
		t.Fatal("the configuration carries no google_connection_options")
	}
	if want := "ORIGNOIP"; string(got) != want {
		t.Errorf("google_connection_options = %q, want %q", got, want)
	}
}

// TestChromeQUICConfigWindow checks the flow-control and datagram values the
// configuration carries: they are the captured ones, and a stack that changed
// its defaults would move them silently.
func TestChromeQUICConfigWindow(t *testing.T) {
	_, quicConfig := chromeQUICConfig(transportOptions{}, "chrome_156")
	if got, want := quicConfig.InitialStreamReceiveWindow, uint64(quicChromeStreamWindow); got != want {
		t.Errorf("the stream window is %d, want %d", got, want)
	}
	if got, want := quicConfig.InitialConnectionReceiveWindow, uint64(quicChromeInitialMaxData); got != want {
		t.Errorf("the connection window is %d, want %d", got, want)
	}
	if got, want := quicConfig.MaxIncomingStreams, int64(quicChromeMaxStreamsBidi); got != want {
		t.Errorf("initial_max_streams_bidi is %d, want %d", got, want)
	}
	if got, want := quicConfig.MaxIncomingUniStreams, int64(quicChromeMaxStreamsUni); got != want {
		t.Errorf("initial_max_streams_uni is %d, want %d", got, want)
	}
	if got, want := quicConfig.MaxDatagramFrameSize, uint64(quicChromeMaxDatagramFrameSize); got != want {
		t.Errorf("max_datagram_frame_size is %d, want %d", got, want)
	}
	if !quicConfig.EnableDatagrams {
		t.Error("the datagram support is off, but Chrome announces H3_DATAGRAM")
	}
	if got, want := quicConfig.InitialPacketSize, uint16(1250); got != want {
		t.Errorf("the Initial packet size is %d, want %d", got, want)
	}
}

// TestChromeQUICVersionInformationShape checks the version_information
// parameter the client sends: the chosen version is QUIC v1, and the second
// version is a GREASE one — every byte of it ends in 0x0a, which is the
// scheme Chrome uses.
func TestChromeQUICVersionInformationShape(t *testing.T) {
	value := quicChromeVersionInformation
	if len(value) != 12 {
		t.Fatalf("version_information is %d bytes, want 12", len(value))
	}
	chosen := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if chosen != 1 {
		t.Errorf("the chosen version is %d, want 1", chosen)
	}
	greased := value[8:12]
	for i, b := range greased {
		if b&0x0f != 0x0a {
			t.Errorf("byte %d of the GREASE version is 0x%02x, want the low nibble 0x0a", i, b)
		}
	}
	if hex.EncodeToString(greased) == "00000000" {
		t.Error("the GREASE version is zero")
	}
}
