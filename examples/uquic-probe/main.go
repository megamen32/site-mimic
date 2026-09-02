package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	tls "github.com/refraction-networking/utls"

	"net/http"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
)

func main() {
	tlsConf := &tls.Config{}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      &quic.Config{},
	}

	// Chrome 152 QUIC: the 115 preset layout upgraded with the two 152-line
	// TLS novelties — post-quantum signature algorithms behind a GREASE value
	// and the unregistered 0xCA34 extension (same payloads as the TCP spec,
	// wire format identical). QUIC transport parameters remain the 115 preset
	// pending a fresh real-152 QUIC capture.
	quicSpec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		log.Fatal(err)
	}
	patchToChrome152(quicSpec.ClientHelloSpec)

	uRoundTripper := http3.GetURoundTripper(roundTripper, &quicSpec, nil)
	defer uRoundTripper.Close()

	hclient := &http.Client{Transport: uRoundTripper}

	addr := "https://quic.tlsfingerprint.io/"
	rsp, err := hclient.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("status:", rsp.Status, "proto:", rsp.Proto)
	fmt.Println("body head:", body.String()[:min(600, body.Len())])
}

// patchToChrome152 upgrades a QUIC TLS spec in place: PQ signature
// algorithms behind GREASE plus the 0xCA34 extension.
func patchToChrome152(spec *tls.ClientHelloSpec) {
	for i, ext := range spec.Extensions {
		if sa, ok := ext.(*tls.SignatureAlgorithmsExtension); ok {
			merged := []tls.SignatureScheme{0x6a6a, 0x0904, 0x0905, 0x0906}
			for _, alg := range sa.SupportedSignatureAlgorithms {
				if alg != 0x6a6a && alg != 0x0904 && alg != 0x0905 && alg != 0x0906 {
					merged = append(merged, alg)
				}
			}
			sa.SupportedSignatureAlgorithms = merged
			spec.Extensions[i] = sa
			break
		}
	}
	data, _ := hex.DecodeString("00b808839a648c9b2d01080582df1302130582df13020608839a648c9b2d010908839a648c9b2d010704d679090b04d67909050582df1302120582df13020f08839a648c9b2d010c0582df13021404d679090708839a648c9b2d010a08839a648c9b2d010b0582df13020e0582df13020104d679090104d679090408839a648c9b2d010d04d679090808839a648c9b2d011204d679090f04d67909060582df13020d04d679090a04d679090d04d679090c08839a648c9b2d0113")
	spec.Extensions = append(spec.Extensions, &tls.GenericExtension{Id: 0xCA34, Data: data})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
