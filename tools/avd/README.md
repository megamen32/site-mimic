# Android emulator capture (AVD)

The rooted-phone path (`../phone/README.md`) is the reference: it measures a
**real device**. An emulator is the fallback when you have no rooted phone,
or when you want a clean, disposable environment to reproduce a capture in.

Two things an emulator does that a real phone does not need:

1. **The CA goes into the emulator's user store**, not the system store:
   `/data/misc/user/0/cacerts-added/<subject_hash_old>.0`, with the
   `system_security_cacerts_file` SELinux context, followed by a reboot
   (the trust store is read at boot). `install_ca.sh` does that.
2. **The app talks to the host through the global HTTP proxy**:
   `settings put global http_proxy 10.0.2.2:<port>` — `10.0.2.2` is the
   emulator's route to the host loopback.

| file | what it does |
| --- | --- |
| `install_ca.sh` | installs the mitm CA into the emulator's user trust store and reboots it |
| `capture.sh` | installs the APK, verifies the installed version, starts mitmdump, drives the app, writes a JSONL capture |

## Capture

```sh
ADB=~/Android/Sdk/platform-tools/adb \
SERIAL=emulator-5554 \
PKG=ru.oneme.app \
APK=/path/to/app.apk \
EXPECT_VERSION=26.35.1 \
URL='https://example.com/' \
sh tools/avd/capture.sh
```

The output is JSONL, one flow per line, with headers in wire order.

## Two lessons that cost a real capture

* **Never trust the file name — trust `dumpsys package`.** A capture
  labelled with one version while the emulator still ran another produces
  a profile of the wrong client, and nothing in the artifact says so.
  `capture.sh` aborts when `versionName` does not match `EXPECT_VERSION`.
* **Emulators do not reproduce the device.** TLS ClientHello shapes differ
  (no real GPU stack, different network stack, different app build). Treat
  an emulator capture as a *methodology* capture; publish a profile from a
  physical device.
