# Capture from a rooted Android phone

Tooling for taking a site-mimic profile off a real phone: the app's own
ClientHello and headers (MAX / `ru.oneme.app` was the reference case) and the
web version of the same service (`web.max.ru` in the phone browser).

Everything here is proven end to end on a Samsung SM-G998B / Android 15 with
root; the measured numbers live in `docs/max-oneme.ru.md`.

| file | where it runs | what it does |
| --- | --- | --- |
| `setup_capture.sh` | on the phone (root) | iptables redirect of one uid's TCP + QUIC block, starts/stops the on-device forwarder |
| `ca_mount.sh` | on the phone (root) | bind-mounts the mitmproxy CA into the conscrypt APEX view of zygote |
| `mitm_capture_addon.py` | on the capture host | mitmproxy addon: writes ClientHello bytes and HTTP headers to JSONL |
| `cdp_headers.py` | on your laptop | reads the browser's request headers over the DevTools protocol (no CA needed) |
| `../cmd/tproxyfwd` | on the phone | transparent TCP → SOCKS5 forwarder (recovers the pre-REDIRECT destination) |
| `../cmd/hello-tap` | on your laptop | plain TCP-level ClientHello tap — the cheap path when you only need JA3/JA4 |

## The chain

```
app (uid) ──TCP──▶ iptables nat REDIRECT :30886
                       │
                       ▼
                 tproxyfwd  ──reads SO_ORIGINAL_DST──▶ SOCKS5 ──▶ mitmdump --mode socks5
                                                                            │
                                                                            ▼
                                                              capture.jsonl (hellos + headers)
```

Two rules carry the whole thing:

1. **Block QUIC for the target uid.** `iptables -A OUTPUT -p udp -m owner
   --uid-owner <uid> --dport 443 -j REJECT`. A modern app speaks HTTP/3 over
   UDP/443 by default; there is no TCP ClientHello to capture, and the
   capture looks empty for a reason that has nothing to do with the app.
   This was the actual cause of the first failed capture of `ru.oneme.app`:
   `ss` showed only `SYN-SENT` probes to port 7, no TLS handshake at all.
2. **Mount the CA into zygote, not into the app.** `su -c mount --bind` into
   the app's own mount namespace is *not* inherited when the app is restarted
   (zygote forks with its own namespace view). Bind-mount into the zygote
   namespace instead — every app forked afterwards inherits the CA view.

On networks that hijack DNS (some office routers) add
`iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 1.1.1.1`
(and the same for TCP/53) — not needed when the capture host is reached over
a VPN.

## Step by step

### 0. Get onto the device

The phone is a shared resource. Take a lease first (it is the only thing
that keeps two agents from fighting over the same iptables rules):

```sh
s21-lease acquire --owner "$USER" --minutes 60 --purpose "capture <app> traffic"
# -> lease id; export it and pass it to every adb call
export S21_LEASE_ID=<lease-id>
```

Connect over adb (TCP link to the host that has the phone, or USB):

```sh
adb -s 127.0.0.1:22221 shell 'id'   # remote adb
adb devices                        # local USB
```

### 1. Find the uid and the package

```sh
adb shell 'stat -c %u /data/data/ru.oneme.app'      # -> 10338
adb shell 'dumpsys package ru.oneme.app | grep userId'
```

The uid is the selector that matters: it also captures the app's helper
processes. For the browser, use the browser's own uid
(`com.android.chrome` → 10279 on the reference phone).

### 2. Push the tools and the CA

```sh
GOOS=linux GOARCH=arm64 go build -o /tmp/tproxyfwd ./cmd/tproxyfwd
adb push /tmp/tproxyfwd /data/local/tmp/tproxyfwd
adb push tools/phone/setup_capture.sh /data/local/tmp/setup_capture.sh
adb push tools/phone/ca_mount.sh     /data/local/tmp/ca_mount.sh

# the mitmproxy CA in Android PEM naming: <subject_hash_old>.0
mitmproxy --version          # ~/.mitmproxy/mitmproxy-ca-cert.pem
openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem \
  | awk '{print $NF}'        # -> c8750f0d
cp ~/.mitmproxy/mitmproxy-ca-cert.pem /data/local/tmp/c8750f0d.0
```

### 3. Start the capture host

On a machine the phone can reach (a VPS with a Tailscale address works well):

```sh
mitmdump --mode socks5 --listen-host 0.0.0.0 --listen-port 31896 \
         --set ssl_insecure=true --set connection_strategy=lazy \
         -s tools/phone/mitm_capture_addon.py \
         --set out_jsonl=/tmp/capture.jsonl
```

* `--mode socks5` — the phone side talks SOCKS5 (the on-device forwarder is
  a SOCKS5 *client*).
* `--set ssl_insecure=true` — the target's own certificate chain does not
  validate (`api2.oneme.ru`); without it mitmproxy refuses the upstream.
* `--set connection_strategy=lazy` — connect upstream only when the client
  actually speaks, otherwise every captured host burns a connection.

### 4. Start the capture on the phone

```sh
adb push tools/phone/setup_capture.sh /data/local/tmp/setup_capture.sh
adb shell "su -c 'PKG=ru.oneme.app SOCKS5=100.65.58.36:31896 \
                   sh /data/local/tmp/setup_capture.sh start'"
# -> CA_MOUNTED, LISTENER_OK, SETUP_DONE
```

Then open the app and let it talk. The rules are uid-scoped, so nothing else
on the phone is affected.

### 5. Read the capture

```sh
go run ./cmd/hellofp /tmp/capture.jsonl     # JA3/JA4 per SNI
```

`hellofp` parses the captured bytes with the library's own
`mimic.ParseClientHello`, so the numbers are the same ones a server would
compute — not a third-party implementation's.

### 6. Tear down (do not skip this)

```sh
adb shell "su -c 'PKG=ru.oneme.app sh /data/local/tmp/setup_capture.sh stop'"
# -> CLEANED
s21-lease release <lease-id>
```

`stop` removes both iptables rules (the TCP redirect and the UDP/443
REJECT) and kills the forwarder. A left-over REJECT rule silently breaks
QUIC for that uid; a left-over redirect sends its traffic into a dead
forwarder. Check with:

```sh
adb shell "su -c 'iptables -t nat -L OUTPUT -n -v'"
adb shell "su -c 'iptables -L OUTPUT -n -v'"
```

## The web version: why CDP, not MITM

For the browser the same chain captures the **ClientHello** (mitmproxy reads
it before the client rejects our certificate) but the browser refuses the
proxy certificate:

```
Client TLS handshake failed. The client does not trust the proxy's
certificate for web.max.ru (tls alert certificate unknown)
```

Chrome 155 uses the **Chrome Root Store**: for browser traffic it does not
consult the Android platform trust store at all. Neither of these works:

* the CA in the conscrypt APEX (mounted into zygote) — the browser ignores
  the platform store;
* the CA in the user store (`/data/misc/keychain/user_0/<hash>.0` with the
  `system_security_cacerts_file` context) — same reason;
* `--ignore-certificate-errors` in `/data/local/tmp/chrome-command-line` —
  modern Chrome ignores that file, and `su` cannot append to the read-only
  `/data/local/tmp/chrome-command-line` anyway.

The DevTools protocol does not need any of it: Chrome itself reports the
headers it is about to send.

```sh
# 1. make the phone's devtools socket reachable
adb forward tcp:9333 localabstract:chrome_devtools_remote
ssh -f -N -L 9334:127.0.0.1:9333 <host-with-the-phone>

# 2. read the headers
python3 tools/phone/cdp_headers.py --cdp 127.0.0.1:9334 \
        --url https://web.max.ru/ --out web.jsonl --seconds 30
```

`cdp_headers.py` calls `Security.setIgnoreCertificateErrors` and
`Network.enable`, then `Page.navigate`, and records every
`Network.requestWillBeSent`.

Two caveats, both important for the profile:

* CDP reports the **browser-added** headers only. `Host`, `Accept`,
  `Accept-Encoding`, `Accept-Language`, `Connection` and the `sec-fetch-*`
  quartet are added by the network stack and are **not** in
  `requestWillBeSent`. Take them from a real navigation (DevTools → Network
  → the document request) or from an existing Chrome profile in
  `examples/profiles/`.
* The websocket connection to the DevTools endpoint must not carry an
  `Origin` header — `websocket.create_connection(..., suppress_origin=True)`.

## Gotchas that cost time

* **Per-app network namespace.** `nsenter -t <pid> -n` on the app shows a
  different netns than the one its sockets live in. The `nat OUTPUT`
  rule with `--uid-owner` is the reliable selector — it matches on the
  socket owner wherever the socket lives.
* **Quoting.** Nested quotes in `adb shell` break the argument parsing
  (`su -c '…'` inside `sh -c '…'`). Push a script with `adb push` and run
  it, or pipe it in base64: `base64 -d > /data/local/tmp/x.sh`.
* **toybox syntax.** `nsenter -t PID -m -- mount --bind src dst` — the `--`
  separator is mandatory on Android 14+.
* **`am force-stop`** after the CA mount: the app must be restarted to
  inherit the zygote's CA view.
* **Do not `pkill -f`** a pattern that matches your own command line — it
  kills the ssh shell that runs it. Kill by PID (`ss -tlnp`), or use
  `pkill -x <name>`.
* The capture host's `/tmp` may be swept by a timer — copy the capture
  off the host as soon as it is written.
