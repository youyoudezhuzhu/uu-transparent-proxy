# redsocks — reference source (vendored, not compiled)

This directory documents the authoritative upstream sources this project's
native daemon algorithm is derived from. The APK ships a **self-contained**
native daemon (`app/src/main/jni/native-lib.c`) that implements the same
transparent-proxy algorithm, so the APK has **no runtime dependency** on
libevent/openssl. The vendored source below is kept verbatim as the reference
implementation and for further study.

## Why vendored not compiled?

- `redsocks` (original) and `redsocks2` (semigodking fork) depend on
  `libevent` (and redsocks2 optionally on `libcrypto`). Shipping those into an
  APK adds ~1–2 MB native bloat and cross-compilation friction.
- The Android NDK already provides `libc`, `liblog`, and pthreads, which is all
  the self-contained daemon needs. The transparent→SOCKS5/HTTP logic is
  self-contained C and is re-implemented to be dependency-free.
- The **algorithm** (iptables REDIRECT + `SO_ORIGINAL_DST` + SOCKS5/HTTP
  CONNECT to the upstream proxy) is identical to redsocks. The UDP path mirrors
  redsocks2's `redudp` (SOCKS5 UDP ASSOCIATE).

## Upstream references

- redsocks (original) — https://github.com/darkk/redsocks
  - `redsocks.c`: TCP transparent → SOCKS4a/5 + HTTP CONNECT, `SO_ORIGINAL_DST`.
- redsocks2 (fork with UDP) — https://github.com/semigodking/redsocks
  - adds `redudp.c`: TPROXY + `IP_RECVORIGDSTADDR` + SOCKS5 UDP ASSOCIATE.
- ProxyDroid — https://github.com/madeye/proxy
  - reference for the iptables `REDIRECT`/`TPROXY` rules and the clean
    add/remove-rule lifecycle used by `IptablesManager.kt`.
- SocksProxy-Android — https://github.com/Julian-Chu/SocksProxy-Android
  - reference for `SO_ORIGINAL_DST` handling and Android proxy architecture.

You can fetch the actual source on demand and drop it here for a full in-tree
reference:

```bash
git clone --depth 1 https://github.com/darkk/redsocks.git this/redsocks
git clone --depth 1 https://github.com/semigodking/redsocks.git this/redsocks2
```

To instead compile redsocks2 into the APK, add a `libevent` NDK build target and
link it — see the CMake options in redsocks2's README. This project deliberately
keeps the daemon dependency-free; see `README.md` → "架构说明".
