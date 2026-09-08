/*
 * native-lib.c — UU Transparent Proxy Gateway native daemon (JNI).
 *
 * Implements the "redsocks algorithm": iptables REDIRECT/TPROXY pulls raw
 * client TCP/UDP into local sockets; this daemon reads the original
 * destination via SO_ORIGINAL_DST / IP_RECVORIGDSTADDR, then wraps the byte
 * stream in SOCKS5 CONNECT or HTTP CONNECT and forwards it to the UU
 * accelerator proxy (default 6.6.6.6:8088). For UDP it implements DNS
 * forwarding + SOCKS5 UDP ASSOCIATE (redudp-style).
 *
 * Logs to logcat tag "uuproxy".
 */
#include <jni.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>

/* SO_ORIGINAL_DST is 80 on Linux; defined here in case headers lag. */
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

#define LOG_TAG "uuproxy"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#define PROTO_SOCKS5 0
#define PROTO_HTTP 1

/* ------------------------------------------------------------------ */
/* Global state                                                         */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running   = 0;
static int  g_protocol   = PROTO_SOCKS5;
static char g_up_host[256] = {0};
static int  g_up_port    = 8088;
static int  g_tcp_port   = 23333;
static int  g_udp_port   = 23334;
static int  g_udp_enabled = 1;

static int  g_tcp_listen_fd = -1;
static int  g_udp_listen_fd = -1;

static atomic_long g_rx = 0;   /* upstream -> client (download)   */
static atomic_long g_tx = 0;   /* client   -> upstream (upload)   */
static atomic_int  g_clients = 0;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void set_timeout(int fd, int secs) {
    struct timeval tv = { secs, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int send_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = send(fd, p, left, MSG_NOSIGNAL);
        if (w <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w; left -= (size_t)w;
    }
    return 0;
}

static int read_exact(int fd, void *buf, size_t n) {
    char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r <= 0) return -1;
        p += r; left -= (size_t)r;
    }
    return 0;
}

static int connect_tcp(const char *host, int port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) == 1) {
        /* numeric IP */
    } else {
        struct hostent *he = gethostbyname(host);
        if (!he) return -1;
        memcpy(&sa.sin_addr, he->h_addr_list[0], sizeof(sa.sin_addr));
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

/* ------------------------------------------------------------------ */
/* Upstream proxy handshake. Returns 0 on success, -1 on failure.       */
/* ------------------------------------------------------------------ */
static int socks5_handshake(int fd, const struct sockaddr_in *orig) {
    /* No-auth greeting */
    unsigned char g[] = {0x05, 0x01, 0x00};
    if (send_all(fd, g, sizeof(g)) != 0) return -1;
    unsigned char rsp[2];
    if (read_exact(fd, rsp, 2) != 0) return -1;
    if (rsp[1] != 0x00) { LOGE("SOCKS5: auth method rejected (%02x)", rsp[1]); return -1; }

    /* CONNECT request: ATYP=1 (IPv4) */
    unsigned char req[10];
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
    memcpy(&req[4], &orig->sin_addr, 4);
    req[8] = (unsigned char)((orig->sin_port >> 8) & 0xff);
    req[9] = (unsigned char)(orig->sin_port & 0xff);
    if (send_all(fd, req, sizeof(req)) != 0) return -1;

    unsigned char hdr[4];
    if (read_exact(fd, hdr, 4) != 0) return -1;
    if (hdr[1] != 0x00) { LOGE("SOCKS5: connect failed code=%02x", hdr[1]); return -1; }
    /* read remaining BND.ADDR/BND.PORT by ATYP */
    int atyp = hdr[3];
    unsigned char rest[22];
    int need = 0;
    if (atyp == 1) need = 4 + 2;
    else if (atyp == 3) { if (read_exact(fd, &rest[0], 1) != 0) return -1; need = rest[0] + 2; }
    else if (atyp == 4) need = 16 + 2;
    else return -1;
    if (need > 0 && read_exact(fd, rest, need) != 0) return -1;
    return 0;
}

static int http_connect_handshake(int fd, const struct sockaddr_in *orig) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &orig->sin_addr, ip, sizeof(ip));
    int port = ntohs(orig->sin_port);
    char req[256];
    int n = snprintf(req, sizeof(req),
                     "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                     "Proxy-Connection: keep-alive\r\nUser-Agent: uuproxy/1.0\r\n\r\n",
                     ip, port, ip, port);
    if (send_all(fd, req, (size_t)n) != 0) return -1;

    /* Read headers until blank line. */
    char buf[1024];
    size_t used = 0;
    for (;;) {
        ssize_t r = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
        if (r <= 0) return -1;
        used += (size_t)r;
        buf[used] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
        if (used >= sizeof(buf) - 1) return -1;
    }
    if (strncmp(buf, "HTTP/1.1", 8) != 0 && strncmp(buf, "HTTP/1.0", 8) != 0) return -1;
    /* status code is tokens 2 after "HTTP/x.y " */
    if (strstr(buf, "200") == NULL) {
        LOGE("HTTP CONNECT failed: %s", buf);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-direction relay thread.                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    int          src_fd;
    int          dst_fd;
    int          dir;        /* 0 = client->upstream (tx), 1 = upstream->client (rx) */
    pthread_t    thread;
    bool         started;
} relay_t;

static void *relay_loop(void *arg) {
    relay_t *r = (relay_t *)arg;
    char buf[16384];
    for (;;) {
        if (!g_running) break;
        ssize_t n = recv(r->src_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (r->dir == 0) atomic_fetch_add_explicit(&g_tx, n, memory_order_relaxed);
        else            atomic_fetch_add_explicit(&g_rx, n, memory_order_relaxed);
        const char *p = buf;
        ssize_t left = n;
        while (left > 0) {
            ssize_t w = send(r->dst_fd, p, left, MSG_NOSIGNAL);
            if (w <= 0) {
                if (errno == EINTR) continue;
                goto done;
            }
            p += w; left -= w;
        }
    }
done:
    shutdown(r->dst_fd, SHUT_WR);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* TCP client handler (one thread per client).                          */
/* ------------------------------------------------------------------ */
static void *tcp_client_handle(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    struct sockaddr_in orig;
    socklen_t olen = sizeof(orig);
    memset(&orig, 0, sizeof(orig));

    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) != 0) {
        /* Fallback: without SO_ORIGINAL_DST we cannot know the target. */
        LOGE("SO_ORIGINAL_DST failed: %s", strerror(errno));
        close(client_fd);
        atomic_fetch_sub(&g_clients, 1);
        return NULL;
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &orig.sin_addr, ip, sizeof(ip));
    LOGI("client %s:%d -> tunnel via %s:%d", ip, ntohs(orig.sin_port), g_up_host, g_up_port);

    int upstream = connect_tcp(g_up_host, g_up_port);
    if (upstream < 0) {
        LOGE("connect upstream failed: %s", strerror(errno));
        close(client_fd);
        atomic_fetch_sub(&g_clients, 1);
        return NULL;
    }
    int rc = (g_protocol == PROTO_HTTP)
             ? http_connect_handshake(upstream, &orig)
             : socks5_handshake(upstream, &orig);
    if (rc != 0) {
        LOGE("upstream proxy handshake failed");
        close(upstream); close(client_fd);
        atomic_fetch_sub(&g_clients, 1);
        return NULL;
    }

    relay_t r0 = { client_fd, upstream, 0, 0, false };  /* tx */
    relay_t r1 = { upstream,  client_fd, 1, 0, false };  /* rx */
    pthread_create(&r0.thread, NULL, relay_loop, &r0);
    pthread_create(&r1.thread, NULL, relay_loop, &r1);
    pthread_join(r0.thread, NULL);
    pthread_join(r1.thread, NULL);

    close(upstream);
    close(client_fd);
    atomic_fetch_sub(&g_clients, 1);
    LOGD("client %s:%d done", ip, ntohs(orig.sin_port));
    return NULL;
}

static void *tcp_listen_loop(void *arg) {
    (void)arg;
    while (g_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int fd = accept(g_tcp_listen_fd, (struct sockaddr *)&caddr, &clen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (!g_running) break;
            continue;
        }
        set_timeout(fd, 0);  /* no timeout for long-lived tunnel */
        atomic_fetch_add(&g_clients, 1);
        pthread_t t;
        pthread_create(&t, NULL, tcp_client_handle, (void *)(intptr_t)fd);
        pthread_detach(t);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* UDP relay: DNS forwarding + SOCKS5 UDP ASSOCIATE (redudp-style).     */
/* ------------------------------------------------------------------ */
typedef struct {
    int tcp_fd;
    int udp_fd;
    struct sockaddr_in relay_addr;
} udp_assoc_t;

static udp_assoc_t *udp_assoc_create(void) {
    udp_assoc_t *a = calloc(1, sizeof(udp_assoc_t));
    if (!a) return NULL;
    a->tcp_fd = connect_tcp(g_up_host, g_up_port);
    if (a->tcp_fd < 0) { free(a); return NULL; }

    /* SOCKS5 greeting */
    unsigned char g[] = {0x05, 0x01, 0x00};
    if (send_all(a->tcp_fd, g, sizeof(g)) != 0) { close(a->tcp_fd); free(a); return NULL; }
    unsigned char rsp[2];
    if (read_exact(a->tcp_fd, rsp, 2) != 0) { close(a->tcp_fd); free(a); return NULL; }
    if (rsp[1] != 0x00) { close(a->tcp_fd); free(a); return NULL; }

    /* UDP ASSOCIATE request with 0.0.0.0:0 */
    unsigned char req[10] = {0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0};
    if (send_all(a->tcp_fd, req, sizeof(req)) != 0) { close(a->tcp_fd); free(a); return NULL; }
    unsigned char hdr[4];
    if (read_exact(a->tcp_fd, hdr, 4) != 0) { close(a->tcp_fd); free(a); return NULL; }
    if (hdr[1] != 0x00) { close(a->tcp_fd); free(a); return NULL; }
    int atyp = hdr[3];
    unsigned char rest[22];
    int need = 0;
    if (atyp == 1) need = 4 + 2;
    else if (atyp == 3) { read_exact(a->tcp_fd, &rest[0], 1); need = rest[0] + 2; }
    else if (atyp == 4) need = 16 + 2;
    if (need > 0 && read_exact(a->tcp_fd, rest, need) != 0) { close(a->tcp_fd); free(a); return NULL; }
    /* parse relay addr (ATYP=1 assumed for typical proxy) */
    memset(&a->relay_addr, 0, sizeof(a->relay_addr));
    if (atyp == 1) {
        memcpy(&a->relay_addr.sin_addr, rest, 4);
        a->relay_addr.sin_port = ((uint16_t)rest[4] << 8) | rest[5];
    } else if (atyp == 3) {
        /* resolve relay host */
        char hbuf[256]; memcpy(hbuf, &rest[0], rest[0]); hbuf[rest[0]] = 0;
        struct hostent *he = gethostbyname(hbuf);
        if (he) memcpy(&a->relay_addr.sin_addr, he->h_addr_list[0], 4);
        a->relay_addr.sin_port = ((uint16_t)rest[rest[0]+1] << 8) | rest[rest[0]+2];
    }
    a->relay_addr.sin_family = AF_INET;

    a->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (a->udp_fd < 0) { close(a->tcp_fd); free(a); return NULL; }
    return a;
}

static void udp_assoc_destroy(udp_assoc_t *a) {
    if (!a) return;
    if (a->udp_fd >= 0) close(a->udp_fd);
    if (a->tcp_fd >= 0) close(a->tcp_fd);
    free(a);
}

static void *udp_listen_loop(void *arg) {
    (void)arg;
    udp_assoc_t *assoc = udp_assoc_create();
    if (!assoc) {
        LOGE("UDP: failed to establish SOCKS5 UDP ASSOCIATE");
        return NULL;
    }
    LOGI("UDP ASSOCIATE established to %s:%d",
         inet_ntoa(assoc->relay_addr.sin_addr), ntohs(assoc->relay_addr.sin_port));

    unsigned char buf[65536];
    while (g_running) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(g_udp_listen_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) {
            if (errno == EINTR) continue;
            if (!g_running) break;
            continue;
        }
        atomic_fetch_add_explicit(&g_tx, n, memory_order_relaxed);

        /* Wrap in SOCKS5 UDP packet: RSV(2) FRAG(1) ATYP(1) + addr + port + data */
        unsigned char pkt[65536 + 300];
        int o = 0;
        pkt[o++]=0; pkt[o++]=0; pkt[o++]=0; pkt[o++]=1;  /* RSV,RSV,FRAG,ATYP=IPv4 */
        memcpy(&pkt[o], &from.sin_addr, 4); o += 4;
        pkt[o++] = (unsigned char)((from.sin_port >> 8) & 0xff);
        pkt[o++] = (unsigned char)(from.sin_port & 0xff);
        memcpy(&pkt[o], buf, (size_t)n); o += (int)n;

        sendto(assoc->udp_fd, pkt, (size_t)o, 0,
               (struct sockaddr *)&assoc->relay_addr, sizeof(assoc->relay_addr));
    }
    udp_assoc_destroy(assoc);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* JNI entry points                                                     */
/* ------------------------------------------------------------------ */
JNIEXPORT jint JNICALL
Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_startProxy(
        JNIEnv *env, jobject thiz,
        jstring up_host, jint up_port, jint protocol,
        jint tcp_port, jint udp_port, jint udp_enabled) {
    (void)thiz;
    if (g_running) return -1;

    const char *h = (*env)->GetStringUTFChars(env, up_host, NULL);
    strncpy(g_up_host, h, sizeof(g_up_host) - 1);
    (*env)->ReleaseStringUTFChars(env, up_host, h);

    g_up_port     = up_port;
    g_protocol    = protocol;
    g_tcp_port    = tcp_port;
    g_udp_port    = udp_port;
    g_udp_enabled = udp_enabled;

    signal(SIGPIPE, SIG_IGN);
    atomic_store(&g_rx, 0);
    atomic_store(&g_tx, 0);
    atomic_store(&g_clients, 0);
    g_running = 1;

    /* TCP listener */
    g_tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in taddr;
    memset(&taddr, 0, sizeof(taddr));
    taddr.sin_family = AF_INET;
    taddr.sin_addr.s_addr = htonl(INADDR_ANY);
    taddr.sin_port = htons((uint16_t)g_tcp_port);
    if (bind(g_tcp_listen_fd, (struct sockaddr *)&taddr, sizeof(taddr)) != 0) {
        LOGE("bind tcp %d failed: %s", g_tcp_port, strerror(errno));
        g_running = 0; close(g_tcp_listen_fd); return -1;
    }
    if (listen(g_tcp_listen_fd, 128) != 0) {
        g_running = 0; close(g_tcp_listen_fd); return -1;
    }

    pthread_t tcp_thread, udp_thread;
    if (pthread_create(&tcp_thread, NULL, tcp_listen_loop, NULL) != 0) {
        g_running = 0; close(g_tcp_listen_fd); return -1;
    }
    pthread_detach(tcp_thread);

    if (g_udp_enabled) {
        g_udp_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        int rcv = 1;
        setsockopt(g_udp_listen_fd, SOL_IP, IP_RECVORIGDSTADDR, &rcv, sizeof(rcv));
        struct sockaddr_in uaddr;
        memset(&uaddr, 0, sizeof(uaddr));
        uaddr.sin_family = AF_INET;
        uaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        uaddr.sin_port = htons((uint16_t)g_udp_port);
        if (bind(g_udp_listen_fd, (struct sockaddr *)&uaddr, sizeof(uaddr)) == 0) {
            pthread_create(&udp_thread, NULL, udp_listen_loop, NULL);
            pthread_detach(udp_thread);
        } else {
            LOGE("bind udp %d failed: %s", g_udp_port, strerror(errno));
            close(g_udp_listen_fd);
            g_udp_listen_fd = -1;
        }
    }

    LOGI("started: upstream=%s:%d proto=%s tcp=%d udp=%d",
         g_up_host, g_up_port, g_protocol == PROTO_HTTP ? "HTTP" : "SOCKS5",
         g_tcp_port, g_udp_port);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_stopProxy(
        JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    g_running = 0;
    if (g_tcp_listen_fd >= 0) { shutdown(g_tcp_listen_fd, SHUT_RDWR); close(g_tcp_listen_fd); g_tcp_listen_fd = -1; }
    if (g_udp_listen_fd >= 0) { close(g_udp_listen_fd); g_udp_listen_fd = -1; }
    LOGI("stopped");
}

JNIEXPORT jlong JNICALL
Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_getRxBytes(
        JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jlong)atomic_load(&g_rx);
}

JNIEXPORT jlong JNICALL
Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_getTxBytes(
        JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jlong)atomic_load(&g_tx);
}

JNIEXPORT jint JNICALL
Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_getActiveClients(
        JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)atomic_load(&g_clients);
}
