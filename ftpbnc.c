#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>

#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC 0
#endif

#define MAX_EVENTS        1024
#define READ_BUF_SIZE     4096
#define OUT_BUF_SIZE      65536
#define IDENT_PRINT_MAX   128
/* Backpressure watermarks for per-direction output buffers */
#define OUTBUF_HIWAT   (OUT_BUF_SIZE * 3 / 4)  /* pause reads when pending > 75% */
#define OUTBUF_LOWAT   (OUT_BUF_SIZE * 1 / 4)  /* resume reads when pending < 25% */


typedef enum {
    CONN_HANDSHAKE = 0,
    CONN_RELAYING
} conn_state_t;

typedef enum {
    EP_KIND_LISTENER = 0,
    EP_KIND_CLIENT,
    EP_KIND_SERVER,
    EP_KIND_IDENT
} endpoint_kind_t;

struct conn;
struct endpoint;

struct outbuf {
    char   data[OUT_BUF_SIZE];
    size_t off;
    size_t len;
};

struct endpoint {
    int             fd;
    endpoint_kind_t kind;
    struct conn    *conn;
};

struct conn {
    int            id;
    struct endpoint client;
    struct endpoint server;
    struct endpoint ident;

    struct outbuf  c2s;
    struct outbuf  s2c;

    conn_state_t   state;
    uint64_t       last_activity;
    uint64_t       connect_start;
    uint64_t       ident_start;

    int            closing;
    int            server_connected;
    int            ident_enabled;
    int            ident_ready;
    int            ident_query_sent;

    char           client_ip[INET6_ADDRSTRLEN];
    uint16_t       client_port;
    uint16_t       server_port;

    char           ident_name[256];

    struct conn   *next;
};

/* Globals */
static int g_epoll_fd = -1;
static int g_listen_fd = -1;
static int g_debug = 0;
static char g_title_storage[128];
static const char *g_title_prefix = NULL;
static struct conn *g_conns = NULL;
static int g_conn_count = 0;
static int g_next_conn_id = 0;
static volatile sig_atomic_t g_running = 1;

extern char **environ;
static char *g_argv_start = NULL;
static size_t g_argv_total_len = 0;

/* Destination / bind configuration */
static char g_dest_host[256];
static char g_dest_port[16];
static char g_bind_host[256];
static char g_bind_port[16];
static uint16_t g_bind_port_num = 0;

/* Resolved once in main(). getaddrinfo() blocks, so it must never run in the event loop. */
static struct sockaddr_storage g_dest_addr;
static socklen_t g_dest_addrlen = 0;
static struct sockaddr_storage g_bind_addr;   /* port 0: source address for outgoing sockets */
static socklen_t g_bind_addrlen = 0;

/* Timeouts (milliseconds) */
static uint64_t g_connect_timeout_ms = 1000;   /* -C, default 1s */
static uint64_t g_ident_timeout_ms   = 500;    /* -I, default 0.5s */
static uint64_t g_idle_timeout_ms    = 0;  /* -L, default unlimited, 0=unlimited */

static int g_ident_global_enabled = 0;

static int epoll_update_endpoint(struct endpoint *ep, uint32_t events);
static void update_events_for_conn(struct conn *c);

/* Time helpers */

static uint64_t now_millis(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

/* Logging */

static void log_debug(const char *fmt, ...) {
    if (!g_debug) return;

    va_list ap;
    va_start(ap, fmt);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);

    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "[%s.%03ld] ", tbuf, (long)(tv.tv_usec / 1000));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void
update_events_for_conn(struct conn *c)
{
    if (!c || c->closing) return;

    /* Client endpoint: we write to client from s2c */
    uint32_t client_events = 0;
    if (c->state == CONN_RELAYING) {
        client_events |= EPOLLIN;
        /* Backpressure: pause reading from client if c2s backlog is high */
        if (c->c2s.len > OUTBUF_HIWAT) {
            client_events &= ~EPOLLIN;
        }
    }
    /* Handshake: no events. Data waits in the kernel; an armed but ignored
     * level-triggered event would spin epoll_wait at 100% CPU. */
    if (c->s2c.len > 0) client_events |= EPOLLOUT;
    epoll_update_endpoint(&c->client, client_events);

    /* Server endpoint: we write to server from c2s */
    uint32_t server_events = 0;
    if (c->state == CONN_RELAYING) {
        server_events |= EPOLLIN;
        /* Backpressure: pause reading from server if s2c backlog is high */
        if (c->s2c.len > OUTBUF_HIWAT) {
            server_events &= ~EPOLLIN;
        }
    } else if (!c->server_connected) {
        /* Handshake: only wait for connect completion; nothing once connected */
        server_events |= EPOLLOUT;
    }
    if (c->c2s.len > 0) server_events |= EPOLLOUT;
    epoll_update_endpoint(&c->server, server_events);
}


static void log_conn(struct conn *c, const char *tag, const char *fmt, ...) {
    if (!g_debug || !c) return;

    char msg[512];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *ip = c->client_ip[0] ? c->client_ip : "?";
    log_debug("[%s] [Client #%d - %s] %s",
              tag ? tag : "BNC",
              c->id,
              ip,
              msg);
}

/* Process title handling */

static void init_proctitle(char **argv, char **envp) {
    (void)envp;
    if (!argv || !argv[0]) return;

    char *start = argv[0];
    char *end = argv[0] + strlen(argv[0]);

    for (int i = 1; argv[i]; i++) {
        if (end + 1 == argv[i]) {
            end = argv[i] + strlen(argv[i]);
        }
    }

    for (char **p = environ; p && *p; p++) {
        if (end + 1 == *p) {
            end = *p + strlen(*p);
        }
    }

    g_argv_start = start;
    g_argv_total_len = (size_t)(end - start);
}

static void update_title(void) {
    if (!g_title_prefix || !g_argv_start || g_argv_total_len == 0) return;

    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%s: %d users", g_title_prefix, g_conn_count);
    if (n < 0) return;

    if ((size_t)n >= g_argv_total_len) {
        n = (int)g_argv_total_len - 1;
        if (n < 0) return;
    }

    memset(g_argv_start, 0, g_argv_total_len);
    memcpy(g_argv_start, buf, (size_t)n);
}

/* Signal handling */

static void signal_handler(int signum) {
    (void)signum;
    g_running = 0;
}

/* TCP helpers */

static int set_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

/* Outbuf helpers */

static size_t outbuf_free_space(struct outbuf *b) {
    return OUT_BUF_SIZE - (b->off + b->len);
}

static void outbuf_compact(struct outbuf *b) {
    if (b->off > 0 && b->len > 0) {
        memmove(b->data, b->data + b->off, b->len);
    }
    b->off = 0;
}

static int outbuf_append(struct outbuf *b, const char *data, size_t len) {
    if (len == 0) return 0;

    if (outbuf_free_space(b) < len) {
        outbuf_compact(b);
        if (outbuf_free_space(b) < len) {
            return -1;
        }
    }

    memcpy(b->data + b->off + b->len, data, len);
    b->len += len;
    return 0;
}

/* SIGPIPE-safe send */

static ssize_t safe_send(int fd, const void *buf, size_t len) {
#ifdef MSG_NOSIGNAL
    return send(fd, buf, len, MSG_NOSIGNAL);
#else
    return send(fd, buf, len, 0);
#endif
}

static int outbuf_flush(struct outbuf *b, int fd) {
    while (b->len > 0) {
        ssize_t n = safe_send(fd, b->data + b->off, b->len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            return -1;
        } else if (n == 0) {
            return -1;
        }
        b->off += (size_t)n;
        b->len -= (size_t)n;
        if (b->len == 0) {
            b->off = 0;
            return 0;
        }
    }
    b->off = 0;
    return 0;
}

/* Connection list */

static void conn_list_add(struct conn *c) {
    c->next = g_conns;
    g_conns = c;
    g_conn_count++;
    update_title();
}

/* Epoll wrapper */

static int epoll_update_endpoint(struct endpoint *ep, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = ep;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, ep->fd, &ev) < 0) {
        if (errno == ENOENT) {
            if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, ep->fd, &ev) < 0) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

/* Connection close / sweep */

static void conn_close(struct conn *c, const char *reason) {
    if (!c || c->closing) return;
    c->closing = 1;

    log_conn(c, "BNC",
             "Closing connections (client_fd=%d, server_fd=%d): %s",
             c->client.fd, c->server.fd,
             reason ? reason : "");

    if (c->client.fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->client.fd, NULL);
        close(c->client.fd);
        c->client.fd = -1;
    }
    if (c->server.fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->server.fd, NULL);
        close(c->server.fd);
        c->server.fd = -1;
    }
    if (c->ident.fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->ident.fd, NULL);
        close(c->ident.fd);
        c->ident.fd = -1;
    }
}

static void conn_sweep_closed(void) {
    struct conn **pp = &g_conns;
    while (*pp) {
        struct conn *c = *pp;
        if (c->closing) {
            *pp = c->next;
            c->next = NULL;
            g_conn_count--;
            update_title();
            free(c);
        } else {
            pp = &(*pp)->next;
        }
    }
}

/* IDNT line building (bounded) */

static void build_idnt_line(struct conn *c, char *buf, size_t buflen) {
    const char *ident = (c->ident_ready && c->ident_name[0]) ? c->ident_name : "*";
    int ident_len = (int)strlen(ident);
    if (ident_len > IDENT_PRINT_MAX) ident_len = IDENT_PRINT_MAX;

    /* IDNT <ident>@<ip>:<hostname>. Hostname is left empty (just the trailing
     * ':') so IPv6 addresses — which contain ':' themselves — stay unambiguous:
     * the last ':' marks where the (empty) hostname begins. */
    const char *ip = c->client_ip[0] ? c->client_ip : "0.0.0.0";
    snprintf(buf, buflen, "IDNT %.*s@%s:\r\n", ident_len, ident, ip);
}

static void start_relay_if_ready(struct conn *c);

/* IDENT */

static void ident_fail(struct conn *c, const char *why) {
    if (!c) return;
    if (c->ident.fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->ident.fd, NULL);
        close(c->ident.fd);
        c->ident.fd = -1;
    }

    if (!c->ident_ready) {
        log_conn(c, "IDENT",
                 "No response (%s); fallback to '*'",
                 why ? why : "unknown");
        strncpy(c->ident_name, "*", sizeof(c->ident_name));
        c->ident_name[sizeof(c->ident_name)-1] = '\0';
        c->ident_ready = 1;
        start_relay_if_ready(c);
    }
}

static void handle_ident_event(struct endpoint *ep, uint32_t events) {
    struct conn *c = ep->conn;
    if (!c || c->closing) return;

    if (events & (EPOLLERR | EPOLLHUP)) {
        ident_fail(c, "EPOLLERR/EPOLLHUP");
        return;
    }

    if (!c->ident_ready && !c->ident_query_sent && (events & EPOLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(ep->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            ident_fail(c, "connect failed");
            return;
        }

        char q[64];
        snprintf(q, sizeof(q), "%u , %u\r\n",
                 (unsigned)c->server_port, (unsigned)c->client_port);

        ssize_t n = safe_send(ep->fd, q, strlen(q));
        if (n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
            ident_fail(c, "write query failed");
            return;
        }
        c->ident_query_sent = 1;

        /* Log without CRLF */
        char q_print[64];
        strncpy(q_print, q, sizeof(q_print) - 1);
        q_print[sizeof(q_print) - 1] = '\0';
        for (int i = (int)strlen(q_print) - 1; i >= 0; --i) {
            if (q_print[i] == '\r' || q_print[i] == '\n')
                q_print[i] = '\0';
            else
                break;
        }
        log_conn(c, "IDENT",
                 "Lookup enabled: sent \"%s\" to client (client_fd=%d, server_fd=%d)",
                 q_print, c->client.fd, c->server.fd);

        epoll_update_endpoint(ep, EPOLLIN);
    }

    if (!c->ident_ready && (events & EPOLLIN)) {
        char buf[512];
        ssize_t n = read(ep->fd, buf, sizeof(buf) - 1);
        if (n <= 0) {
            ident_fail(c, "read failed");
            return;
        }
        buf[n] = '\0';

        int p1, p2;
        char user[256];
        user[0] = '\0';

        int r = sscanf(buf, " %d , %d : USERID :%*[^:]:%255s", &p1, &p2, user);
        if (r == 3 && user[0]) {
            for (char *p = user; *p; ++p) {
                if (*p == '\r' || *p == '\n') {
                    *p = '\0';
                    break;
                }
            }
            strncpy(c->ident_name, user, sizeof(c->ident_name));
            c->ident_name[sizeof(c->ident_name)-1] = '\0';
            log_conn(c, "IDENT",
                     "Response: \"%s\" (client_port=%u)",
                     c->ident_name, (unsigned)c->client_port);
        } else {
            strncpy(c->ident_name, "*", sizeof(c->ident_name));
            c->ident_name[sizeof(c->ident_name)-1] = '\0';
            log_conn(c, "IDENT",
                     "Parse failed, using '*'; raw response: \"%s\"",
                     buf);
        }

        c->ident_ready = 1;

        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, ep->fd, NULL);
        close(ep->fd);
        ep->fd = -1;

        start_relay_if_ready(c);
    }
}

/* Server connect completion */

static void handle_server_connected(struct conn *c) {
    if (!c || c->closing)
        return;

    /* Already processed? Then ignore further EPOLLOUTs */
    if (c->server_connected)
        return;

    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(c->server.fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        log_conn(c, "BNC",
                 "Server connect failed: %s", strerror(err ? err : errno));
        conn_close(c, "connect failed");
        return;
    }

    log_conn(c, "BNC",
             "Established to %s:%s (client_fd=%d, server_fd=%d)",
             g_dest_host, g_dest_port, c->client.fd, c->server.fd);

    c->server_connected = 1;
    start_relay_if_ready(c);
    if (!c->closing && c->state == CONN_HANDSHAKE)
        update_events_for_conn(c);   /* still waiting on ident: disarm the server fd */
}

/* Write / read handlers */
static void
handle_write(struct endpoint *ep)
{
    struct conn *c = ep->conn;
    if (!c || c->closing) return;

    struct outbuf *b = NULL;

    if (ep->kind == EP_KIND_CLIENT) {
        b = &c->s2c;
    } else if (ep->kind == EP_KIND_SERVER) {
        b = &c->c2s;
    } else {
        return;
    }

    if (b->len == 0) {
        update_events_for_conn(c);
        return;
    }

    if (outbuf_flush(b, ep->fd) < 0) {
        conn_close(c, "write error");
        return;
    }

    /* If we drained below LOWAT, re-enable reads via update_events_for_conn */
    update_events_for_conn(c);
}

static void
handle_read(struct endpoint *ep)
{
    struct conn *c = ep->conn;
    if (!c || c->closing) return;

    /* Do not relay data before handshake finished */
    if (c->state == CONN_HANDSHAKE) {
        return;
    }

    struct endpoint *peer_ep = NULL;
    struct outbuf  *peer_buf = NULL;

    if (ep->kind == EP_KIND_CLIENT) {
        peer_ep  = &c->server;
        peer_buf = &c->c2s;
    } else if (ep->kind == EP_KIND_SERVER) {
        peer_ep  = &c->client;
        peer_buf = &c->s2c;
    } else {
        return;
    }

    /* If we're already heavily backpressured, stop reading */
    if (peer_buf->len > OUTBUF_HIWAT) {
        update_events_for_conn(c);
        return;
    }

    char buf[READ_BUF_SIZE];

    for (;;) {
        ssize_t n = read(ep->fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            conn_close(c, "read error");
            return;
        } else if (n == 0) {
            log_conn(c, "BNC",
                     "%s closed (fd=%d)",
                     ep->kind == EP_KIND_CLIENT ? "Client" : "Server",
                     ep->fd);
            conn_close(c, "EOF");
            return;
        }

        c->last_activity = now_millis();

        /* Peer already closed? */
        if (peer_ep->fd < 0) {
            conn_close(c, "peer closed");
            return;
        }

        /*
         * CRITICAL TLS FIX:
         * If there is any pending data in the peer buffer, we must not
         * direct-send newer data ahead of it. Append everything to buffer.
         */
        if (peer_buf->len > 0) {
            if (outbuf_append(peer_buf, buf, (size_t)n) < 0) {
                conn_close(c, "output buffer overflow");
                return;
            }
            update_events_for_conn(c);

            /* Apply backpressure if we crossed HIWAT */
            if (peer_buf->len > OUTBUF_HIWAT) {
                break;
            }
            continue;
        }

        /*
         * Fast path: no backlog -> attempt direct send.
         * Any remainder goes into the buffer.
         */
        ssize_t w = safe_send(peer_ep->fd, buf, (size_t)n);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                w = 0;
            } else {
                conn_close(c, "peer write error");
                return;
            }
        }

        if (w < n) {
            size_t remaining = (size_t)(n - w);
            if (outbuf_append(peer_buf, buf + w, remaining) < 0) {
                conn_close(c, "output buffer overflow");
                return;
            }
            update_events_for_conn(c);

            if (peer_buf->len > OUTBUF_HIWAT) {
                break;
            }
        } else {
            /* No buffering needed; keep events up to date */
            update_events_for_conn(c);
        }
    }
}

/* Timeouts */

static void check_timeouts(void) {
    uint64_t now = now_millis();
    struct conn *c = g_conns;
    while (c) {
        struct conn *next = c->next;

        if (!c->closing) {
            if (!c->server_connected && g_connect_timeout_ms > 0) {
                uint64_t age = now - c->connect_start;
                if (age > g_connect_timeout_ms) {
                    conn_close(c, "connect timeout");
                }
            }

            if (c->ident_enabled && !c->ident_ready && g_ident_timeout_ms > 0) {
                uint64_t age = now - c->ident_start;
                if (age > g_ident_timeout_ms) {
                    ident_fail(c, "ident timeout");
                }
            }

            if (!c->closing && c->state == CONN_RELAYING && g_idle_timeout_ms > 0) {
                uint64_t idle = now - c->last_activity;
                if (idle > g_idle_timeout_ms) {
                    conn_close(c, "idle timeout");
                }
            }
        }

        c = next;
    }
}

/* Create outgoing socket bound to g_bind_host */

static int create_bound_socket(int family) {
    if (family != g_bind_addr.ss_family) {
        log_debug("bind(local): address family mismatch");
        return -1;
    }

    int sfd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sfd == -1)
        return -1;

    set_nodelay(sfd);

    if (bind(sfd, (const struct sockaddr *)&g_bind_addr, g_bind_addrlen) < 0) {
        log_debug("bind(local) failed: %s", strerror(errno));
        close(sfd);
        return -1;
    }
    return sfd;
}

/* Start IDENT connection (if enabled) */

static void conn_start_ident(struct conn *c) {
    c->ident.fd = -1;
    c->ident.kind = EP_KIND_IDENT;
    c->ident.conn = c;
    c->ident_ready = 0;
    c->ident_query_sent = 0;

    if (!c->ident_enabled)
        return;

    if (!c->client_ip[0]) {
        ident_fail(c, "no client_ip");
        return;
    }

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_NUMERICHOST;   /* client_ip is already numeric; never hit DNS */

    int ret = getaddrinfo(c->client_ip, "113", &hints, &res);
    if (ret != 0) {
        log_debug("getaddrinfo(ident) failed: %s", gai_strerror(ret));
        ident_fail(c, "getaddrinfo failed");
        return;
    }

    int sfd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = create_bound_socket(rp->ai_family);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                log_debug("connect(ident) failed immediately: %s", strerror(errno));
                close(sfd);
                sfd = -1;
                continue;
            }
        }
        break;
    }

    freeaddrinfo(res);

    if (sfd == -1) {
        ident_fail(c, "socket/connect failed");
        return;
    }

    c->ident.fd = sfd;
    c->ident_start = now_millis();

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = &c->ident;
    ev.events   = EPOLLOUT | EPOLLIN;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, c->ident.fd, &ev) < 0) {
        log_debug("epoll add ident failed: %s", strerror(errno));
        close(c->ident.fd);
        c->ident.fd = -1;
        ident_fail(c, "epoll add failed");
        return;
    }
}

/* Start relaying when both server + ident are ready */

static void
start_relay_if_ready(struct conn *c)
{
    if (!c || c->closing) return;
    if (c->state == CONN_RELAYING) return;
    if (!c->server_connected) return;
    if (!c->ident_ready) return;

    /* Build IDNT line */
    char line[256];
    build_idnt_line(c, line, sizeof(line));

    /* Log printable version without CR/LF */
    char printable[256];
    strncpy(printable, line, sizeof(printable) - 1);
    printable[sizeof(printable) - 1] = '\0';
    for (int i = (int)strlen(printable) - 1; i >= 0; --i) {
        if (printable[i] == '\r' || printable[i] == '\n')
            printable[i] = '\0';
        else
            break;
    }

    log_conn(c, "IDENT",
             "Sent to backend server: %s",
             printable);

    /* Queue IDNT line to server (never direct-send here) */
    if (outbuf_append(&c->c2s, line, strlen(line)) < 0) {
        conn_close(c, "IDNT buffer overflow");
        return;
    }

    /* Switch to relaying state */
    c->state = CONN_RELAYING;

    /*
     * IMPORTANT:
     * Do NOT manually twiddle epoll flags here.
     * Let the centralized event updater apply correct EPOLLIN/OUT
     * with backpressure taken into account.
     */
    update_events_for_conn(c);
}


/* Connection creation */

static struct conn *conn_create(int client_fd, const struct sockaddr_storage *pss, socklen_t slen) {
    struct conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->id = ++g_next_conn_id;

    c->client.fd   = client_fd;
    c->client.kind = EP_KIND_CLIENT;
    c->client.conn = c;

    c->server.fd   = -1;
    c->server.kind = EP_KIND_SERVER;
    c->server.conn = c;

    c->ident.fd    = -1;
    c->ident.kind  = EP_KIND_IDENT;
    c->ident.conn  = c;

    c->state = CONN_HANDSHAKE;
    c->last_activity = now_millis();
    c->connect_start = c->last_activity;
    c->ident_start   = 0;

    c->closing = 0;
    c->server_connected = 0;

    c->c2s.off = c->c2s.len = 0;
    c->s2c.off = c->s2c.len = 0;

    c->ident_enabled = g_ident_global_enabled;
    c->ident_ready   = 0;
    c->ident_query_sent = 0;

    strncpy(c->ident_name, "*", sizeof(c->ident_name));
    c->ident_name[sizeof(c->ident_name)-1] = '\0';

    c->client_ip[0] = '\0';
    c->client_port = 0;
    c->server_port = g_bind_port_num;

    if (pss && slen > 0) {
        if (pss->ss_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)pss;
            inet_ntop(AF_INET, &sin->sin_addr, c->client_ip, sizeof(c->client_ip));
            c->client_port = ntohs(sin->sin_port);
        } else if (pss->ss_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)pss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, c->client_ip, sizeof(c->client_ip));
            c->client_port = ntohs(sin6->sin6_port);
        }
    }

    int sfd = create_bound_socket(g_dest_addr.ss_family);
    if (sfd != -1 &&
        connect(sfd, (const struct sockaddr *)&g_dest_addr, g_dest_addrlen) == -1 &&
        errno != EINPROGRESS) {
        log_debug("connect(dest) failed immediately: %s", strerror(errno));
        close(sfd);
        sfd = -1;
    }

    if (sfd == -1) {
        free(c);
        return NULL;
    }

    c->server.fd = sfd;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = &c->client;
    ev.events   = 0;   /* handshake: nothing to relay yet; EPOLLERR/HUP still arrive */
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, c->client.fd, &ev) < 0) {
        log_debug("epoll add client failed: %s", strerror(errno));
        close(sfd);
        free(c);
        return NULL;
    }

    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = &c->server;
    ev.events   = EPOLLOUT;   /* connect completion only */
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, c->server.fd, &ev) < 0) {
        log_debug("epoll add server failed: %s", strerror(errno));
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, c->client.fd, NULL);
        close(sfd);
        free(c);
        return NULL;
    }

    conn_list_add(c);

    log_conn(c, "NEW",
             "%s:%u (client_fd=%d, server_fd=%d)",
             c->client_ip[0] ? c->client_ip : "?",
             (unsigned)c->client_port, c->client.fd, c->server.fd);

    if (c->ident_enabled) {
        conn_start_ident(c);
    } else {
        c->ident_ready = 1;
    }

    return c;
}

/* Accept new clients */

static void handle_accept(void) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept4(g_listen_fd, (struct sockaddr *)&ss, &slen,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EMFILE || errno == ENFILE) {
                log_debug("Too many open files; rejecting connection");
            } else {
                log_debug("accept error: %s", strerror(errno));
            }
            break;
        }

        set_nodelay(cfd);

        if (!conn_create(cfd, &ss, slen)) {
            log_debug("Failed to create connection object");
            close(cfd);
        }
    }
}

/* Daemonize */

static int daemonize(void) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);

    if (setsid() < 0)
        return -1;

    pid = fork();
    if (pid < 0)
        return -1;
    if (pid > 0)
        _exit(0);

    umask(0);
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }

    return 0;
}

/* Parse "host:port" with last ':' separator */

static int parse_host_port(const char *arg, char *host, size_t hostlen, char *port, size_t portlen) {
    const char *colon = strrchr(arg, ':');
    if (!colon || colon == arg || *(colon+1) == '\0') {
        return -1;
    }

    size_t hlen = (size_t)(colon - arg);
    if (hlen >= hostlen) return -1;

    memcpy(host, arg, hlen);
    host[hlen] = '\0';

    if (strlen(colon + 1) >= portlen) return -1;
    strcpy(port, colon + 1);

    return 0;
}

/* Usage */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -d dest_host:port -b bind_host:port [-t title] [-v] [-i]\n"
        "            [-C connect_ms] [-I ident_ms] [-L idle_ms]\n"
        "\n"
        "  -d dest_host:port  Destination FTP server (IPv4/IPv6)\n"
        "  -b bind_host:port  Local bind address and port (IPv4/IPv6)\n"
        "  -t title           Process title prefix (\"title: N users\")\n"
        "  -v                 Verbose/debug (no daemonize)\n"
        "  -i                 Enable IDENT lookup to client (port 113)\n"
        "  -C connect_ms      FTP server connect timeout in ms (default 10000)\n"
        "  -I ident_ms        IDENT timeout in ms (default 2000)\n"
        "  -L idle_ms         Idle timeout in ms (default 600000, 0 = unlimited)\n",
        prog);
}

/* Listening socket */

static int create_listen_socket(void) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;

    int ret = getaddrinfo(g_bind_host, g_bind_port, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo(bind) failed: %s\n", gai_strerror(ret));
        return -1;
    }

    int fd = -1;
    int optval = 1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (fd == -1)
            continue;

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
#endif

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (listen(fd, SOMAXCONN) == 0) {
                break;
            }
        }

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd == -1) {
        fprintf(stderr, "Failed to bind/listen on %s:%s\n", g_bind_host, g_bind_port);
        return -1;
    }

    log_debug("Listening on %s:%s", g_bind_host, g_bind_port);
    return fd;
}

/* Event loop */

static void event_loop(void) {
    struct epoll_event events[MAX_EVENTS];
    int timeout_ms = 100;
    uint64_t next_timeout_check = now_millis() + 100;

    while (g_running) {
        int n = epoll_wait(g_epoll_fd, events, MAX_EVENTS, timeout_ms);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            struct epoll_event *ev = &events[i];
            if (!ev->data.ptr)
                continue;

            struct endpoint *ep = (struct endpoint *)ev->data.ptr;

            if (ep->kind == EP_KIND_LISTENER) {
                handle_accept();
                continue;
            }

            struct conn *c = ep->conn;
            if (!c || c->closing)
                continue;

            uint32_t e = ev->events;

            if (ep->kind == EP_KIND_IDENT) {
                handle_ident_event(ep, e);
                continue;
            }

            if (e & (EPOLLERR | EPOLLHUP)) {
                conn_close(c, "EPOLLERR/EPOLLHUP");
                continue;
            }

            if (ep->kind == EP_KIND_SERVER &&
                c->state == CONN_HANDSHAKE && (e & EPOLLOUT)) {
                handle_server_connected(c);
                if (c->closing) continue;
            }

            if (e & EPOLLIN) {
                handle_read(ep);
                if (c->closing) continue;
            }
            if (e & EPOLLOUT) {
                if (!(ep->kind == EP_KIND_SERVER && c->state == CONN_HANDSHAKE)) {
                    handle_write(ep);
                }
            }
        }

        uint64_t now = now_millis();
        if (now >= next_timeout_check) {
            check_timeouts();
            next_timeout_check = now + 100;
        }

        conn_sweep_closed();
    }

    struct conn *c = g_conns;
    while (c) {
        struct conn *next = c->next;
        conn_close(c, "shutdown");
        c = next;
    }
    conn_sweep_closed();
}

/* main */

int main(int argc, char **argv, char **envp) {
    init_proctitle(argv, envp);

    g_dest_host[0] = g_dest_port[0] = '\0';
    g_bind_host[0] = g_bind_port[0] = '\0';
    g_title_storage[0] = '\0';
    g_title_prefix = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "vd:b:t:iC:I:L:")) != -1) {
        switch (opt) {
        case 'v':
            g_debug = 1;
            break;
        case 'd':
            if (parse_host_port(optarg, g_dest_host, sizeof(g_dest_host),
                                g_dest_port, sizeof(g_dest_port)) != 0) {
                fprintf(stderr, "Invalid -d dest_host:port\n");
                usage(argv[0]);
                return 1;
            }
            break;
        case 'b':
            if (parse_host_port(optarg, g_bind_host, sizeof(g_bind_host),
                                g_bind_port, sizeof(g_bind_port)) != 0) {
                fprintf(stderr, "Invalid -b bind_host:port\n");
                usage(argv[0]);
                return 1;
            }
            break;
        case 't':
            strncpy(g_title_storage, optarg, sizeof(g_title_storage) - 1);
            g_title_storage[sizeof(g_title_storage) - 1] = '\0';
            g_title_prefix = g_title_storage;
            break;
        case 'i':
            g_ident_global_enabled = 1;
            break;
        case 'C': {
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (!end || *end != '\0') {
                fprintf(stderr, "Invalid -C connect_ms\n");
                return 1;
            }
            g_connect_timeout_ms = (uint64_t)v;
            break;
        }
        case 'I': {
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (!end || *end != '\0') {
                fprintf(stderr, "Invalid -I ident_ms\n");
                return 1;
            }
            g_ident_timeout_ms = (uint64_t)v;
            break;
        }
        case 'L': {
            char *end = NULL;
            unsigned long long v = strtoull(optarg, &end, 10);
            if (!end || *end != '\0') {
                fprintf(stderr, "Invalid -L idle_ms\n");
                return 1;
            }
            g_idle_timeout_ms = (uint64_t)v;   /* 0 = unlimited */
            break;
        }
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (g_dest_host[0] == '\0' || g_bind_host[0] == '\0') {
        usage(argv[0]);
        return 1;
    }

    /* Parse bind port number for ident queries */
    {
        char *end = NULL;
        long port = strtol(g_bind_port, &end, 10);
        if (!end || *end != '\0' || port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid bind port: %s\n", g_bind_port);
            return 1;
        }
        g_bind_port_num = (uint16_t)port;
    }

    /* Resolve bind and dest once. A hostname here is looked up at startup only;
     * a DNS change needs a restart. */
    {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_flags    = AI_PASSIVE;

        int ret = getaddrinfo(g_bind_host, NULL, &hints, &res);
        if (ret != 0) {
            fprintf(stderr, "getaddrinfo(bind) failed: %s\n", gai_strerror(ret));
            return 1;
        }
        memcpy(&g_bind_addr, res->ai_addr, res->ai_addrlen);
        g_bind_addrlen = res->ai_addrlen;
        freeaddrinfo(res);

        hints.ai_flags  = 0;
        hints.ai_family = g_bind_addr.ss_family;   /* dest must match bind family */
        ret = getaddrinfo(g_dest_host, g_dest_port, &hints, &res);
        if (ret != 0) {
            fprintf(stderr, "getaddrinfo(dest) failed: %s\n", gai_strerror(ret));
            return 1;
        }
        memcpy(&g_dest_addr, res->ai_addr, res->ai_addrlen);
        g_dest_addrlen = res->ai_addrlen;
        freeaddrinfo(res);
    }

    if (!g_debug) {
        if (daemonize() != 0) {
            fprintf(stderr, "Failed to daemonize\n");
            return 1;
        }
    }

    if (g_title_prefix) {
        update_title();
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }

    g_listen_fd = create_listen_socket();
    if (g_listen_fd < 0) {
        close(g_epoll_fd);
        return 1;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    static struct endpoint listen_ep;
    listen_ep.fd   = g_listen_fd;
    listen_ep.kind = EP_KIND_LISTENER;
    listen_ep.conn = NULL;

    ev.events   = EPOLLIN;
    ev.data.ptr = &listen_ep;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_listen_fd, &ev) < 0) {
        perror("epoll_ctl listen");
        close(g_listen_fd);
        close(g_epoll_fd);
        return 1;
    }

    log_debug("Starting event loop");
    event_loop();

    close(g_listen_fd);
    close(g_epoll_fd);

    return 0;
}
