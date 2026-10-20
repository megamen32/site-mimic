package mimic

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ja4QUIC is the FoxIO JA4 in its QUIC form: the same computation as
// ClientHello.JA4 (the "t" form) with the protocol letter swapped, exactly
// what tools/ja3_ja4.py's compute_ja4(trace, "q") does.
func ja4QUIC(h *ClientHello) string {
	ja4a := "q" + h.ja4VersionToken() + h.ja4SNIToken() +
		pad2(len(stripGREASE(h.CipherSuites))) + pad2(len(stripGREASE(h.Extensions))) + h.ja4ALPNToken()
	return ja4a + "_" + h.ja4B() + "_" + h.ja4C()
}

// quicClientHello builds the ClientHello bytes the QUIC stack puts into the
// first Initial packet, without touching the network: uTLS' QUIC connection
// hands the handshake message over as its first write event.
func quicClientHello(t *testing.T, spec *utls.ClientHelloSpec) []byte {
	t.Helper()
	cfg := &utls.QUICConfig{TLSConfig: &utls.Config{
		ServerName: "quic.example",
		MinVersion: utls.VersionTLS13,
	}}
	conn := utls.UQUICClient(cfg, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		t.Fatalf("apply preset: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Start(ctx); err != nil {
		t.Fatalf("start handshake: %v", err)
	}
	defer conn.Close()
	for {
		ev := conn.NextEvent()
		switch ev.Kind {
		case utls.QUICNoEvent:
			t.Fatal("no client hello was written")
		case utls.QUICWriteData:
			if ev.Level == utls.QUICEncryptionLevelInitial {
				return append([]byte(nil), ev.Data...)
			}
		}
	}
}

// helloRecord wraps a TLS handshake message in a record header, so the
// library's ClientHello parser can read it — QUIC carries handshake messages
// without records, but the bytes inside are the same.
func helloRecord(msg []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01, byte(len(msg) >> 8), byte(len(msg))}
	return append(rec, msg...)
}

func TestChrome152QUICSpecShape(t *testing.T) {
	spec, err := chrome152QUICSpec()
	if err != nil {
		t.Fatalf("chrome152QUICSpec: %v", err)
	}
	hello := spec.ClientHelloSpec
	if hello == nil {
		t.Fatal("spec has no client hello")
	}

	// The extension set: the Chrome 115 preset's ten extensions plus the
	// 0xCA34 the 152 novelties add.
	if got, want := len(hello.Extensions), 11; got != want {
		t.Errorf("extension count = %d, want %d", got, want)
	}

	var ca34 *utls.GenericExtension
	var sigAlgs *utls.SignatureAlgorithmsExtension
	var qtp *utls.QUICTransportParametersExtension
	for _, ext := range hello.Extensions {
		switch e := ext.(type) {
		case *utls.GenericExtension:
			if e.Id == chrome152CA34ExtID {
				ca34 = e
			}
		case *utls.SignatureAlgorithmsExtension:
			sigAlgs = e
		case *utls.QUICTransportParametersExtension:
			qtp = e
		}
	}
	if ca34 == nil {
		t.Fatalf("no 0x%04X extension in the QUIC hello", chrome152CA34ExtID)
	}
	if got, want := hex.EncodeToString(ca34.Data), chrome152CA34PayloadHex; got != want {
		t.Errorf("0xCA34 payload = %s, want %s", got, want)
	}
	if sigAlgs == nil {
		t.Fatal("no signature_algorithms extension in the QUIC hello")
	}
	for _, want := range []utls.SignatureScheme{
		chrome152GREASESigAlg,
		chrome152PQSigAlgMLDSA44,
		chrome152PQSigAlgMLDSA65,
		chrome152PQSigAlgMLDSA87,
	} {
		if !hasSignatureScheme(sigAlgs.SupportedSignatureAlgorithms, want) {
			t.Errorf("signature algorithm 0x%04x missing", uint16(want))
		}
	}
	if qtp == nil {
		t.Fatal("no quic transport parameters extension in the QUIC hello")
	}
}

// TestChrome152QUICMatchesTCPSchemes ties the QUIC spec to the TCP one: the
// post-quantum signature algorithms must be the same set the TCP path sends
// (mimic/spec152.go), so the two never drift apart.
func TestChrome152QUICMatchesTCPSchemes(t *testing.T) {
	tcp, err := chrome152Spec()
	if err != nil {
		t.Fatalf("chrome152Spec: %v", err)
	}
	quicSpec, err := chrome152QUICSpec()
	if err != nil {
		t.Fatalf("chrome152QUICSpec: %v", err)
	}
	tcpAlgs := signatureAlgorithms(tcp)
	quicAlgs := signatureAlgorithms(quicSpec.ClientHelloSpec)
	for _, want := range []utls.SignatureScheme{
		chrome152GREASESigAlg,
		chrome152PQSigAlgMLDSA44,
		chrome152PQSigAlgMLDSA65,
		chrome152PQSigAlgMLDSA87,
	} {
		if !hasSignatureScheme(tcpAlgs, want) {
			t.Errorf("TCP spec misses signature algorithm 0x%04x", uint16(want))
		}
		if !hasSignatureScheme(quicAlgs, want) {
			t.Errorf("QUIC spec misses signature algorithm 0x%04x", uint16(want))
		}
	}
}

// TestChrome152QUICTransportParameters checks the transport parameters against
// the values captured from a real Android Chrome QUIC hello.
// TestChrome152QUICTransportParameters pins the transport parameters to the
// bytes of a real Chrome 152.
//
// The expected values are written out as the hex they take on the wire, not
// as references to the implementation's constants. The previous version of
// this test compared the implementation against a copy of its own constants,
// so it passed whatever both said — change a value and both sides moved
// together. Here a changed value breaks the test.
//
// The values are the ones decoded from the phone capture, in the QUIC
// variable-length encoding: 30000 is 80 00 75 30, 1472 is 45 c0, and so on.
func TestChrome152QUICTransportParameters(t *testing.T) {
	spec, err := chrome152QUICSpec()
	if err != nil {
		t.Fatalf("chrome152QUICSpec: %v", err)
	}
	params := transportParameters(spec.ClientHelloSpec)
	if params == nil {
		t.Fatal("no quic transport parameters extension")
	}

	raw := params.TransportParameters.Marshal()
	got := map[uint64]string{}
	var greaseID uint64
	for id, value := range decodeTransportParameters(t, raw) {
		if isGREASETransportParamID(id) {
			greaseID = id
			continue
		}
		got[id] = hex.EncodeToString(value)
	}

	want := map[uint64]string{
		0x01:   "80007530",                 // max_idle_timeout = 30000 ms
		0x03:   "45c0",                     // max_udp_payload_size = 1472
		0x04:   "80f00000",                 // initial_max_data = 15 MiB
		0x05:   "80600000",                 // initial_max_stream_data_bidi_local = 6 MiB
		0x06:   "80600000",                 // initial_max_stream_data_bidi_remote = 6 MiB
		0x07:   "80600000",                 // initial_max_stream_data_uni = 6 MiB
		0x08:   "4064",                     // initial_max_streams_bidi = 100
		0x09:   "4067",                     // initial_max_streams_uni = 103
		0x0f:   "",                         // initial_source_connection_id — empty on purpose
		0x11:   "0000000100000001dada2a0a", // version_information: chosen 1, available [1, GREASE]
		0x20:   "80010000",                 // max_datagram_frame_size = 64 KiB
		0x3128: "4f5249474543435049573258", // google_connection_options = "ORIGECCPIW2X"
	}
	if len(got) != len(want) {
		t.Errorf("%d transport parameters, want %d (%v)", len(got), len(want), got)
	}
	for id, wantHex := range want {
		gotHex, ok := got[id]
		if !ok {
			t.Errorf("transport parameter 0x%02x missing", id)
			continue
		}
		if gotHex != wantHex {
			t.Errorf("transport parameter 0x%02x = %s, want %s", id, gotHex, wantHex)
		}
	}

	// The GREASE transport parameter: a random id, the captured 6-byte value.
	if greaseID == 0 {
		t.Error("no GREASE transport parameter")
	} else if v := hex.EncodeToString(decodeTransportParameters(t, raw)[greaseID]); v != "7063534da942" {
		t.Errorf("GREASE transport parameter value = %s, want 7063534da942", v)
	}
}

// decodeTransportParameters reads a marshalled transport parameter list into
// id -> value bytes.
func decodeTransportParameters(t *testing.T, raw []byte) map[uint64][]byte {
	t.Helper()
	out := map[uint64][]byte{}
	for pos := 0; pos < len(raw); {
		id, n, ok := readVarint(raw[pos:])
		if !ok {
			t.Fatalf("truncated parameter id at %d", pos)
		}
		pos += n
		length, n, ok := readVarint(raw[pos:])
		if !ok {
			t.Fatalf("truncated parameter length at %d", pos)
		}
		pos += n
		if pos+int(length) > len(raw) {
			t.Fatalf("parameter 0x%02x claims %d bytes, only %d left", id, length, len(raw)-pos)
		}
		out[id] = raw[pos : pos+int(length)]
		pos += int(length)
	}
	return out
}

// readVarint reads a QUIC variable-length integer and returns its value and
// the number of bytes it took.
func readVarint(b []byte) (uint64, int, bool) {
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
		// Big-endian accumulation, then drop the two length bits the
		// marker occupies.
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		return v & 0x3fffffffffffffff, 8, true
	}
}

// TestChrome152QUICClientHelloFingerprint builds the ClientHello the QUIC
// stack sends and fingerprints it the way a server would: the FoxIO JA4 in
// its QUIC form. The extension count and the 0xCA34 / post-quantum payloads
// are what make the hello look like Chrome 152's.
func TestChrome152QUICClientHelloFingerprint(t *testing.T) {
	spec, err := chrome152QUICSpec()
	if err != nil {
		t.Fatalf("chrome152QUICSpec: %v", err)
	}
	msg := quicClientHello(t, spec.ClientHelloSpec)
	hello, err := ParseClientHello(helloRecord(msg))
	if err != nil {
		t.Fatalf("parse client hello: %v", err)
	}

	if got, want := len(hello.Extensions), 11; got != want {
		t.Errorf("hello carries %d extensions, want %d", got, want)
	}
	if _, ok := hello.ExtensionData[chrome152CA34ExtID]; !ok {
		t.Errorf("hello has no 0x%04X extension", chrome152CA34ExtID)
	}
	if got, want := hex.EncodeToString(hello.ExtensionData[chrome152CA34ExtID]), chrome152CA34PayloadHex; got != want {
		t.Errorf("hello 0xCA34 payload = %s, want %s", got, want)
	}
	for _, want := range []uint16{
		uint16(chrome152GREASESigAlg),
		uint16(chrome152PQSigAlgMLDSA44),
		uint16(chrome152PQSigAlgMLDSA65),
		uint16(chrome152PQSigAlgMLDSA87),
	} {
		if !hasSignatureScheme16(hello.SigAlgs, want) {
			t.Errorf("hello signature algorithms miss 0x%04x", want)
		}
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "h3" {
		t.Errorf("hello ALPN = %v, want [h3]", hello.ALPN)
	}
	if got, want := len(hello.CipherSuites), 3; got != want {
		t.Errorf("hello offers %d cipher suites, want %d", got, want)
	}

	ja4 := ja4QUIC(hello)
	t.Logf("QUIC ClientHello JA4: %s", ja4)
	// The shape is what a server fingerprints: TLS 1.3, SNI present, three
	// cipher suites, eleven extensions, ALPN h3.
	if !strings.HasPrefix(ja4, "q13d0311h3_") {
		t.Errorf("QUIC JA4 = %s, want the q13d0311h3_ form", ja4)
	}
}

func hasSignatureScheme(algs []utls.SignatureScheme, want utls.SignatureScheme) bool {
	for _, a := range algs {
		if a == want {
			return true
		}
	}
	return false
}

func hasSignatureScheme16(algs []uint16, want uint16) bool {
	for _, a := range algs {
		if a == want {
			return true
		}
	}
	return false
}

func signatureAlgorithms(spec *utls.ClientHelloSpec) []utls.SignatureScheme {
	for _, ext := range spec.Extensions {
		if sa, ok := ext.(*utls.SignatureAlgorithmsExtension); ok {
			return sa.SupportedSignatureAlgorithms
		}
	}
	return nil
}

func transportParameters(spec *utls.ClientHelloSpec) *utls.QUICTransportParametersExtension {
	for _, ext := range spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			return qtp
		}
	}
	return nil
}

// isGREASETransportParamID reports whether the id is a GREASE transport
// parameter id (the 0x1b..0x3a family RFC 9000 defines for them).
func isGREASETransportParamID(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}
