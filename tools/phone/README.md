# Capture from a rooted Android phone

Tooling for taking a site-mimic profile off a real phone: the app's own
ClientHello and headers (MAX / `ru.oneme.app` was the reference case) and the
web version of the same service (`web.max.ru` in the phone browser).

Everything here is proven end to end on a rooted Android 15 phone with
root; the measured numbers live in `docs/max-oneme.ru.md`.

| file | where it runs | what it does |
| --- | --- | --- |
| `setup_capture.sh` | on the phone (root) | iptables redirect of one uid's TCP + QUIC block, CA mount, and the full teardown (rules, forwarder, CA unmount **and CA files deleted**) |
| `ca_mount.sh` | on the phone (root) | bind-mounts the mitmproxy CA into the conscrypt APEX view of zygote |
| `mitm_capture_addon.py` | on the capture host | mitmproxy addon: writes ClientHello bytes and HTTP headers to JSONL |
| `cdp_headers.py` | on your laptop | reads the browser's request headers over the DevTools protocol (no CA needed) |
| `build_patched_apk.sh` | on your laptop | rebuilds the app with the capture CA embedded in **its own** trust config — the phone's system store stays clean |
| `phone_ui_drive.sh` | on your laptop | drives the phone (tap, tap-by-node, screenshot, UI dump) so the capture is aligned with a known action |
| `phone_ui_find.py` | on your laptop | finds a node in a uiautomator dump and prints its tap centre |
| `tproxy_leg.sh` | on the phone | fallback capture leg over a reverse SSH tunnel, for a phone that is not on USB |
| `capture_ignore_hosts.sh` | on the capture host | the hosts to tunnel instead of decrypting (those pin outside the app) |
| `../cmd/tproxyfwd` | on the phone | transparent TCP → SOCKS5 forwarder (recovers the pre-REDIRECT destination) |
| `../cmd/hello-tap` | on your laptop | plain TCP-level ClientHello tap — the cheap path when you only need JA3/JA4 |

## The forwarder

`../cmd/tproxyfwd` is the on-device half of the chain: a self-contained
static binary (standard library only, it speaks SOCKS5 itself) that
recovers the pre-REDIRECT destination and tunnels the connection upstream.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' \
  -o /tmp/tproxyfwd ./cmd/tproxyfwd
adb push /tmp/tproxyfwd /data/local/tmp/tproxyfwd
adb shell "su -c 'chmod 700 /data/local/tmp/tproxyfwd'"
```

The one-byte domain length in the SOCKS5 CONNECT is not cosmetic. With a
two-byte length the proxy reads the high byte (`0x00`) as the length, sees
an empty host, and stitches the port together from the leftover length byte
and the first character of the address — mitmdump then reports
`Error in TCP connection to :3889` for the destination `155.212.204.150:7`
(`0x0F` = length of the address, `0x31` = `'1'`). Every connection fails,
the capture stays empty, and the error text points at DNS instead of at the
encoder. `cmd/tproxyfwd/socks5_test.go` locks the wire format.

Validated on a rooted Android phone against `ru.oneme.app` on 2026-10-20 with this
tooling: the capture reproduced the committed fingerprint exactly —
JA3 md5 `fb1972c15d60b7be0427edfbd00affde`, JA4
`t13d171100_5b57614c22b0_40271e0a5736`, 17 cipher suites, 11 extensions, no
ALPN (`mimic/testdata/max_app_clienthello_full.json`).


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
that keeps two agents from fighting over the same iptables rules). If your
site wraps `adb` in a guard, the lease id is what the guard asks for:

```sh
# whatever your site calls it — the point is that the device is reserved
device-lease acquire --owner "$USER" --minutes 60 --purpose "capture <app> traffic"
# -> lease id; export it and pass it to every adb call
export LEASE_ID=<lease-id>
```

Connect over adb (TCP link to the host that has the phone, or USB):

```sh
adb -s <host>:<port> shell 'id'   # remote adb
adb devices                       # local USB
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
adb shell "su -c 'PKG=ru.oneme.app SOCKS5=<capture-host>:31896 \
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
# -> CA_UNMOUNTED, CLEANED
device-lease release <lease-id>
```

**Only the certificate has to go.** That is the whole rule: the CA is a root
of trust in the device's trust store, and the apps that read the store (bank
and payment clients, anti-fraud SDKs) start failing on it — so the CA and
its mounts are removed when a capture ends. Everything else may stay: the
helper scripts, the forwarder binary, the logs. They trust nothing, they
are re-pushable in a second, and on a shared phone they belong to whoever
uses the device next.

`stop` removes both iptables rules (the TCP redirect and the UDP/443
REJECT), kills the forwarder, **unmounts the CA bind-mount and deletes the CA
files**. The unmount matters twice over: a left-over `REJECT` rule silently
breaks QUIC for that uid, a left-over redirect sends its traffic into a dead
forwarder, and a left-over CA in the zygote's mount namespace keeps a
mitmproxy root in the system trust store of every app forked afterwards — on
a shared phone that is a hole you do not want to leave open. The CA *files*
(`/data/local/tmp/*.0`) are removed for the same reason: a file on disk is a
root waiting to be mounted again.

```sh
# a phone that is not on USB: the capture host must be reachable another way
adb shell "su -c 'PKG=ru.oneme.app DNS_HIJACK=1 ADB_KEEPALIVE=1 \
                   sh /data/local/tmp/setup_capture.sh start'"
```

* `DNS_HIJACK=1` — force DNS to 1.1.1.1 (routers that hijack DNS make the
  app talk to the wrong host, and the capture looks like an app bug).
* `ADB_KEEPALIVE=1` — accept inbound adb, which stock Android drops when
  the USB host sleeps and which otherwise kills the capture mid-run.

The CA mounts **stack**: every `start` adds another layer over
`/apex/com.android.conscrypt/cacerts`, and a single `umount` only peels off
the top one. `stop` unmounts in a loop until the mount is gone, then the
check must show zero CA files in the zygote view:

```sh
adb shell "su -c 'iptables -t nat -L OUTPUT -n -v'"
adb shell "su -c 'iptables -L OUTPUT -n -v'"
adb shell "su -c 'pidof tproxyfwd || echo none'"
adb shell "su -c 'nsenter -t \$(pidof zygote64) -m -- ls /apex/com.android.conscrypt/cacerts | grep -c c8750f0d'"
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

## Driving the phone

A capture is only worth something if the client did something. `adb shell
input tap` is enough, but the coordinates break the moment the resolution
or the app layout changes — so find the node instead of guessing:

```sh
export SERIAL=<host>:<port> OUT_DIR=/tmp/cap
sh tools/phone/phone_ui_drive.sh wsize
sh tools/phone/phone_ui_drive.sh shot before          # screenshot
sh tools/phone/phone_ui_drive.sh uidump              # -> $OUT_DIR/ui.xml
sh tools/phone/phone_ui_drive.sh tapid "button_play" # tap the node's centre
sh tools/phone/phone_ui_drive.sh act "started playback"
```

`tapid` resolves the node by substring against a uiautomator dump and
prefers clickable nodes (a container often carries the same text as the
button inside it). Every action is appended to `$OUT_DIR/phone_actions.log`
with a timestamp, so the capture and the actions can be correlated after
the fact.

## When the app pins the certificate

Some apps pin their certificate and ignore the system store entirely. Two
ways past it:

1. **The patched APK** (`build_patched_apk.sh`) — the capture CA is embedded
   in the app's *own* trust configuration, so the phone's system trust store
   stays clean and nothing has to be mounted into zygote. The app must be
   started by explicit component afterwards, because a re-signed build
   breaks app-link verification.
2. **A tunnel instead of a decryption** (`capture_ignore_hosts.sh`) — hosts
   that pin outside the app bundle (an OIDC browser, Play services, an
   obfuscated transport) are proxied but *not* decrypted:

   ```sh
   IGNORE_HOSTS=$(sh tools/phone/capture_ignore_hosts.sh)
   mitmdump --mode socks5 --ignore-hosts "$IGNORE_HOSTS" ...
   ```

   Decrypting them anyway is what produces the "TLS handshake failed" spam
   and the "we were MITM'd" telemetry. Do not put the target's own API hosts
   in that list — a decrypted request to the host you are profiling is the
   whole point.

## The leg: adb reverse or SSH

The normal leg is `adb reverse tcp:<port> tcp:<port>`, which needs a working
USB/adb link. When the phone is on its own network, the capture host is
reachable only if the phone dials it: `tproxy_leg.sh` raises a reverse SSH
tunnel from the phone (Termux) and refuses to run while USB is attached, so
the two legs never compete for the same port.

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
