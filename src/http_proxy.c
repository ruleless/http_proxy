#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/event_compat.h>

#include "util.h"
#include "thread_env.h"

#define DebugLog 1
#define InfoLog  2
#define WarnLog  3
#define ErrLog   4

#define LOG(lv, fmt, ...)                                               \
    do {                                                                \
        char env_[1024] = {0};                                          \
        time_t t_ = time(NULL);                                         \
        struct tm *timeinfo_ = localtime(&t_);                          \
        get_logenv(env_, sizeof(env_));                                 \
        if (DebugLog == lv) {                                           \
            fprintf(stderr, "[%04d/%02d/%d %02d:%02d:%02d][" #lv "]"    \
                    "[%s:%d][%s]" fmt "%s\n",                           \
                    timeinfo_->tm_year + 1900, timeinfo_->tm_mon + 1,   \
                    timeinfo_->tm_mday, timeinfo_->tm_hour,             \
                    timeinfo_->tm_min, timeinfo_->tm_sec,               \
                    __FILE__, __LINE__, __FUNCTION__,                   \
                    ##__VA_ARGS__, env_);                               \
        } else {                                                        \
            fprintf(stderr, "[%04d/%02d/%d %02d:%02d:%02d][" #lv "]"    \
                    fmt "%s\n",                                         \
                    timeinfo_->tm_year + 1900, timeinfo_->tm_mon + 1,   \
                    timeinfo_->tm_mday, timeinfo_->tm_hour,             \
                    timeinfo_->tm_min, timeinfo_->tm_sec,               \
                    ##__VA_ARGS__, env_);                               \
        }                                                               \
    } while (0)

#define SNPRINTF(key)                                                   \
    do {                                                                \
        const char *env_ = get_thread_env(key);                         \
        if (env_ && *env_) {                                            \
            int n_ = snprintf(ptr, end_ptr - ptr, key ":%s ", env_);    \
            if (n_ < 0 || n_ >= end_ptr - ptr) {                        \
                return;                                                 \
            }                                                           \
            ptr += n_;                                                  \
        }                                                               \
    } while(0)

#define MAX_HEADER    512
#define HOSTNAME_SIZE 256
#define MAX_BUF       4096
#define TUN_TIMEOUT   60
#define PROXY_TIMEOUT 60

#define BOOL  int
#define TRUE  1
#define FALSE 0

#define CONNECTION_RESPONSE "HTTP/1.0 200 Connection established"
#define ENV_TUNNEL   "TUNNEL"
#define ENV_PROXY    "PROXY"
#define ENV_HOST     "HOST"
#define ENV_TUNFD    "tunfd"
#define ENV_PROXYFD  "prxoyfd"

typedef struct server_s server_t;
typedef struct http_tunnel_s http_tunnel_t;
typedef struct http_proxy_s http_proxy_t;

typedef struct hostname_s hostname_t;
struct hostname_s {
    char hostname[HOSTNAME_SIZE];
    int port;
};

struct server_s {
    int fd;

    struct event ev_accept;
    struct event_base *evbase;
    struct evdns_base *evdns;
};

struct http_tunnel_s {
    int fd;

    BOOL http_connected;
    char header[MAX_HEADER + 1];
    int header_len;
    hostname_t host;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    server_t *server;
    http_proxy_t *proxy;

    char buf[MAX_BUF];
    size_t len;
    char *wptr;
};

struct http_proxy_s {
    int fd;
    BOOL connected;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    http_tunnel_t *tun;

    char buf[MAX_BUF];
    size_t len;
    char *wptr;
};

static void accept_cb(evutil_socket_t fd, short event, void *arg);

static void signal_cb(evutil_socket_t fd, short event, void *arg);

static http_tunnel_t *new_tunnel(server_t *s, int fd);
static void free_tunnel(http_tunnel_t *tun);
static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg);
static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg);
static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg);
static int reply_estab_msg(http_tunnel_t *tun);

static http_proxy_t *new_proxy(http_tunnel_t *tun, const struct sockaddr *addr, socklen_t addrlen);
static void free_proxy(http_proxy_t *proxy);
static void proxy_recv_cb(evutil_socket_t fd, short event, void *arg);
static void proxy_send_cb(evutil_socket_t fd, short event, void *arg);

static int set_nonblock(int fd)
{
    int s = fcntl(fd, F_GETFL);
    if (s < 0) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, s|O_NONBLOCK) < 0) {
        return -1;
    }

    return 0;
}

static void get_logenv(char *env, size_t len)
{
    char *ptr = env + 1, *end_ptr = env + len;

    SNPRINTF(ENV_TUNNEL);
    SNPRINTF(ENV_TUNFD);
    SNPRINTF(ENV_PROXY);
    SNPRINTF(ENV_PROXYFD);
    SNPRINTF(ENV_HOST);
    if (ptr > env + 1) {
        *env = '<';
        *(ptr - 1) = '>';
    }
}

static void set_tunnel_env(const http_tunnel_t *tun)
{
    char t[32], p[32], h[256], tunfd[8], proxyfd[8];

    snprintf(t, sizeof(t), "%p", tun);
    snprintf(tunfd, sizeof(tunfd), "%d", tun->fd);
    snprintf(p, sizeof(p), "%p", tun->proxy);
    if (tun->proxy) {
        snprintf(proxyfd, sizeof(proxyfd), "%d", tun->proxy->fd);
        set_thread_env(ENV_PROXYFD, proxyfd);
    }
    if (*tun->host.hostname && tun->host.port) {
        snprintf(h, sizeof(h), "%s:%d", tun->host.hostname, tun->host.port);
    } else {
        snprintf(h, sizeof(h), "acquiring");
    }
    set_thread_env(ENV_TUNNEL, t);
    set_thread_env(ENV_TUNFD, tunfd);
    set_thread_env(ENV_PROXY, p);
    set_thread_env(ENV_HOST, h);
}

static BOOL valid_hostname(const char *h)
{
    while (*h) {
        if (!isalnum(*h) && *h != '-' && *h != '.') {
            return FALSE;
        }
        h++;
    }

    return TRUE;
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event *signal = arg;

    LOG(InfoLog, "signal_cb: got signal %d", event_get_signal(signal));
}

static server_t *new_server(struct event_base *evbase, struct evdns_base *evdns, int port)
{
    server_t *s;
    int fd;
    int opt;
    struct sockaddr_in bindaddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG(WarnLog, "create server failed. %s", strerror(errno));
        return NULL;
    }
    if (set_nonblock(fd) < 0) {
        LOG(WarnLog, "create server failed. %s", strerror(errno));
        goto err_1;
    }

    opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = htons(port);
    bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (const struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0) {
        LOG(WarnLog, "create server failed. bind addr failed, %s", strerror(errno));
        goto err_1;
    }
    if (listen(fd, 5) < 0) {
        LOG(WarnLog, "create server failed. listen failed, %s", strerror(errno));
        goto err_1;
    }

    s = (server_t *)calloc(sizeof(*s), 1);
    if (!s) {
        goto err_1;
    }
    s->fd = fd;
    s->evbase = evbase;
    s->evdns = evdns;

    event_assign(&s->ev_accept, evbase, fd, EV_READ|EV_PERSIST, accept_cb, s);
    event_add(&s->ev_accept, NULL);

    return s;

err_1:
    if (s) {
        free(s);
    }
    if (fd >= 0) {
        close(fd);
    }

    return NULL;
}

static void free_server(server_t *s)
{
    event_del(&s->ev_accept);
    free(s);
}

static void accept_cb(evutil_socket_t fd, short event, void *arg)
{
    server_t *s = (server_t *)arg;
    int clifd = accept(s->fd, NULL, NULL);
    http_tunnel_t *tun;

    clear_thread_env();
    if (clifd < 0) {
        LOG(WarnLog, "accept client failed, %s", strerror(errno));
        return;
    }
    if (set_nonblock(clifd) < 0) {
        goto err_1;
    }

    if (!(tun = new_tunnel(s, clifd))) {
        LOG(WarnLog, "accpet client failed, create tunnel error");
        goto err_1;
    }

    LOG(DebugLog, "step 1. accept client");

    return;

err_1:
    if (clifd >= 0) {
        close(clifd);
    }
}

static http_tunnel_t *new_tunnel(server_t *s, int fd)
{
    http_tunnel_t *tun;

    tun = (http_tunnel_t *)calloc(sizeof(*tun), 1);
    if (!tun) {
        LOG(WarnLog, "create tunnel failed. no enough memory");
        return NULL;
    }

    tun->fd = fd;
    tun->http_connected = FALSE;
    *tun->header = '\0';
    tun->header_len = 0;
    tun->server = s;

    tun->proxy = NULL;
    *tun->buf = '\0';
    tun->len = 0;

    memset(&tun->host, 0, sizeof(tun->host));

    tun->timeout.tv_sec = TUN_TIMEOUT;
    tun->timeout.tv_usec = 0;

    set_tunnel_env(tun);
    LOG(DebugLog, "new tunnel");
    event_assign(&tun->ev_read, s->evbase, fd, EV_READ|EV_PERSIST, tunnel_recv_cb, tun);
    event_assign(&tun->ev_write, s->evbase, fd, EV_WRITE|EV_PERSIST, tunnel_send_cb, tun);
    event_add(&tun->ev_read, &tun->timeout);

    return tun;
}

static void free_tunnel(http_tunnel_t *tun)
{
    if (tun) {
        LOG(DebugLog, "free tunnel");
        event_del(&tun->ev_read);
        event_del(&tun->ev_write);
        if (tun->fd >= 0) {
            close(tun->fd);
        }

        free(tun);
    }
}

enum EParseRet {
    ParseRet_Succuss,
    ParseRet_Again,
    ParseRet_Error,
};

static enum EParseRet parse_header(http_tunnel_t *tun)
{
    const char *ptr = NULL, *end_ptr = NULL;
    char *wptr;
    int i;

    ptr = strstr(tun->header, "\r\n\r\n");
    if (!ptr) {
        return ParseRet_Again;
    }

    ptr = strcasestr(tun->header, "Host:");
    if (!ptr) {
        LOG(InfoLog, "parse http header error, header:\n%s", tun->header);
        return ParseRet_Error;
    }
    ptr += 5;
    while (isspace(*ptr)) {
        ptr++;
    }
    end_ptr = strstr(ptr, "\r\n");
    if (!end_ptr) {
        LOG(WarnLog, "invalid Host field, no '\\r\\n' in the line end", tun->header);
        return ParseRet_Error;
    }

    if (end_ptr - ptr > sizeof(tun->host.hostname) - 1) {
        LOG(WarnLog, "hostname too long, header:\n%s", tun->header);
        return ParseRet_Error;
    }

    wptr = tun->host.hostname;
    for (i = 0; !isspace(*(ptr + i)) && *(ptr + i) != ':'; i++) {
        *wptr++ = *(ptr + i);
    }
    *wptr = '\0';
    tun->host.port = 80;
    if ((ptr = strchr(ptr, ':'))) {
        ptr += 1;
        sscanf(ptr, "%d", &tun->host.port);
        if (tun->host.port < 0) {
            tun->host.port = 0;
        }
    }
    if (!valid_hostname(tun->host.hostname)) {
        LOG(InfoLog, "invalid hostname, header:\n%s", tun->header);
        return ParseRet_Error;
    }

    return ParseRet_Succuss;
}

static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    http_tunnel_t *tun = (http_tunnel_t *)arg;
    struct evutil_addrinfo hints;
    int n, len;
    enum EParseRet rparse;

    set_tunnel_env(tun);
    if (EV_TIMEOUT == event) {
        LOG(InfoLog, "http tunnel timeout");
        free_proxy(tun->proxy);
        free_tunnel(tun);
        goto end;
    }

    /* build http proxy tunnel */

    if (!tun->http_connected) {
  again_1:
        n = recv(tun->fd, tun->header + tun->header_len, MAX_HEADER - tun->header_len, 0);

        if (n < 0) {
            if (EINTR == errno) {
                goto again_1;
            } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
                LOG(WarnLog, "read http tunnel(connecting) failed, %s", strerror(errno));
                free_tunnel(tun);
                goto end;
            }

            goto end;
        }
        if (n == 0) {
            LOG(DebugLog, "http tunnel closed");
            free_tunnel(tun);
            goto end;
        }

        tun->header_len += n;
        tun->header[tun->header_len] = '\0';
        rparse = parse_header(tun);
        if (ParseRet_Error == rparse) {
            LOG(InfoLog, "parse Http Connection Header failed");
            free_tunnel(tun);
            goto end;
        }
        if (ParseRet_Again == rparse) {
            if (tun->header_len == MAX_HEADER) {
                LOG(WarnLog, "no enough space to store http header");
                free_tunnel(tun);
                goto end;
            }
            goto end;
        }

        event_del(&tun->ev_read);
        tun->http_connected = TRUE;
        LOG(DebugLog, "step 2. recv Http Connect Header:\n%s, n:%d, header len:%d",
            tun->header, n, tun->header_len);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = EVUTIL_AI_CANONNAME;
        evdns_getaddrinfo(tun->server->evdns, tun->host.hostname, NULL, &hints, resolv_cb, tun);

        goto end;
    }

    /* read data from client */

    if (!tun->proxy) {
        LOG(ErrLog, "proxy connection with %s:%d is not ready",
            tun->host.hostname, tun->host.port);
        free_tunnel(tun);
        goto end;
    }

again_2:
    assert(!tun->wptr && "tunnel_recv_cb: !tun->wptr");
    n = recv(tun->fd, tun->buf + tun->len, sizeof(tun->buf) - tun->len, 0);

    if (n < 0) {
        if (EINTR == errno) {
            goto again_2;
        } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
            LOG(InfoLog, "read http tunnel with proxy %s:%d failed, %s",
                tun->host.hostname, tun->host.port, strerror(errno));
            free_proxy(tun->proxy);
            free_tunnel(tun);
            goto end;
        }

        goto end;
    }
    if (n == 0) {
        LOG(InfoLog, "http tunnel with proxy connected to %s:%d closed",
            tun->host.hostname, tun->host.port);
        free_proxy(tun->proxy);
        free_tunnel(tun);
        goto end;
    }

    tun->len += n;
    LOG(DebugLog, "recv from client, n:%d, len:%zu", n, tun->len);

    /* translate data to proxy connection */

again_3:
    len = tun->len;
    n = send(tun->proxy->fd, tun->buf, len, 0);
    if (n < 0) {
        if (EINTR == errno) {
            goto again_3;
        } else if (EAGAIN == errno || EWOULDBLOCK == errno) {
            event_del(&tun->ev_read); /* stop to read from client */
            event_add(&tun->proxy->ev_write, NULL);

            tun->wptr = tun->buf;
            goto end;
        }

        LOG(WarnLog, "send to proxy server error, %s", strerror(errno));
        free_proxy(tun->proxy);
        free_tunnel(tun);
        goto end;
    }

    if (n != len) {
        event_del(&tun->ev_read); /* stop to read from client */
        event_add(&tun->proxy->ev_write, NULL);

        tun->wptr = tun->buf + n;
        goto end;
    }

    tun->len = 0;

end:
    clear_thread_env();
}

static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg)
{
    http_tunnel_t *tun = (http_tunnel_t *)arg;
    http_proxy_t *proxy = tun->proxy;
    int n, len;

    assert(event != EV_TIMEOUT && "tunnel_send_cb: event != EV_TIMEOUT");
    assert(proxy && "tunnel_send_cb: proxy != NULL");
    assert(proxy->wptr && "tunnel_send_cb: proxy->wptr != NULL");
    assert(proxy->buf + proxy->len > proxy->wptr && "tunnel_send_cb: buf + len > wptr");

    set_tunnel_env(tun);

again:
    len = proxy->buf + proxy->len - proxy->wptr;
    n = send(tun->fd, proxy->wptr, len, 0);
    if (n < 0) {
        if (EINTR == errno) {
            goto again;
        } else if (EAGAIN == errno || EWOULDBLOCK == errno) {
            goto end;
        }

        LOG(WarnLog, "send to client error(in callback), %s", strerror(errno));
        free_proxy(proxy);
        free_tunnel(tun);
        goto end;
    }

    if (n != len) {
        proxy->wptr += n;
        goto end;
    }

    event_del(&tun->ev_write);
    event_add(&proxy->ev_read, &proxy->timeout);
    proxy->wptr = NULL;
    proxy->len = 0;

end:
    clear_thread_env();
}

static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg)
{
    http_tunnel_t *tun = (http_tunnel_t *)arg;
    int i;

    set_tunnel_env(tun);
    if (err) {
        goto err_1;
    }

    for (i = 0; ai; ai = ai->ai_next, ++i) {
        char buf[128];

        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            struct sockaddr_in servaddr;
            evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));

            servaddr.sin_addr.s_addr = sin->sin_addr.s_addr;
            servaddr.sin_port = htons(tun->host.port);
            servaddr.sin_family = AF_INET;

            LOG(DebugLog, "step 3. resolve %s -> %s, now create proxy to %s:%d",
                tun->host.hostname, buf, buf, tun->host.port);

            tun->proxy = new_proxy(tun, (const struct sockaddr *)&servaddr, sizeof(servaddr));
            if (!tun->proxy) {
                LOG(ErrLog, "create proxy to %s failed", buf);
                free_tunnel(tun);
                goto end;
            }
            if (tun->proxy->connected && reply_estab_msg(tun) < 0) {
                LOG(ErrLog, "reply established message failed, shutdown tunnel");
                free_proxy(tun->proxy);
                free_tunnel(tun);
                goto end;
            }

            if (tun->proxy->connected) {
                LOG(DebugLog, "step 4. directed connected to %s:%d", buf, tun->host.port);
                event_add(&tun->ev_read, &tun->timeout); /* begin to recv from client */
                LOG(DebugLog, "create proxy succuss, proxy is connected");
            } else {
                LOG(DebugLog, "create proxy succuss, proxy to %s:%d is connecting", tun->host.hostname, tun->host.port);
            }

            goto end;
        }
    }

err_1:
    LOG(DebugLog, "resolve '%s' failed, %s",
        tun->host.hostname, evutil_gai_strerror(err));
    free_tunnel(tun);

end:
    clear_thread_env();
}

static int reply_estab_msg(http_tunnel_t *tun)
{
    char msg[MAX_HEADER + 1];
    int n, r;

    snprintf(msg, sizeof(msg),
             "%s\r\n"
             "\r\n",
             CONNECTION_RESPONSE);
    n = strlen(msg);

    if ((r = send(tun->fd, msg, n, 0)) != n) {
        LOG(ErrLog, "reply established message failed, r=%d, %s", r, strerror(errno));
        return -1;
    }

    return 0;
}

static http_proxy_t *new_proxy(http_tunnel_t *tun, const struct sockaddr *addr, socklen_t addrlen)
{
    int fd = -1;
    http_proxy_t *proxy = NULL;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG(WarnLog, "create proxy socket failed, %s", strerror(errno));
        return NULL;
    }
    if (set_nonblock(fd) < 0) {
        LOG(WarnLog, "set nonblock for proxy socket failed, %s", strerror(errno));
        goto err_1;
    }

    proxy = (http_proxy_t *)calloc(sizeof(*proxy), 1);
    if (!proxy) {
        LOG(ErrLog, "create proxy failed, no enough memory");
        goto err_1;
    }

    set_tunnel_env(tun);
    LOG(DebugLog, "new proxy");

    proxy->fd = fd;
    proxy->connected = FALSE;
    proxy->tun = tun;
    proxy->timeout.tv_sec = PROXY_TIMEOUT;
    proxy->timeout.tv_usec = 0;

    event_assign(&proxy->ev_read, tun->server->evbase, fd, EV_READ|EV_PERSIST, proxy_recv_cb, proxy);
    event_assign(&proxy->ev_write, tun->server->evbase, fd, EV_WRITE|EV_PERSIST, proxy_send_cb, proxy);

again:
    if (connect(fd, addr, addrlen) < 0) {
        if (EINTR == errno) {
            goto again;
        } else if (EINPROGRESS == errno) {
            event_add(&proxy->ev_write, NULL);
        } else {
            LOG(ErrLog, "create proxy error, connect failed, reason:%s", strerror(errno));
            goto err_2;
        }
    } else {
        event_add(&proxy->ev_read, NULL);
        proxy->connected = TRUE;
    }

    return proxy;

err_2:
    if (proxy) {
        free(proxy);
    }
err_1:
    if (fd >= 0) {
        close(fd);
    }

    return NULL;
}

static void free_proxy(http_proxy_t *proxy)
{
    if (proxy) {
        LOG(DebugLog, "free proxy, proxy:%p", proxy);
        proxy->connected = FALSE;

        event_del(&proxy->ev_read);
        event_del(&proxy->ev_write);
        if (proxy->fd >= 0) {
            close(proxy->fd);
        }

        free(proxy);
    }
}

static void proxy_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    http_proxy_t *proxy = (http_proxy_t *)arg;
    http_tunnel_t *tun = proxy->tun;
    int n, len;

    assert(tun && "proxy_recv_cb tunnel is null");

    set_tunnel_env(tun);
    if (EV_TIMEOUT == event) {
        LOG(DebugLog, "proxy connection with %s:%d timeout",
            tun->host.hostname, tun->host.port);
        free_proxy(proxy);
        free_tunnel(tun);
        goto end;
    }

    /* recv data from remote server */

again_1:
    assert(!proxy->wptr && "proxy_recv_cb: !proxy->wptr");
    n = recv(proxy->fd, proxy->buf + proxy->len, sizeof(proxy->buf) - proxy->len, 0);

    if (n < 0) {
        if (EINTR == errno) {
            goto again_1;
        } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
            LOG(InfoLog, "read proxy connection with %s:%d failed, %s",
                tun->host.hostname, tun->host.port, strerror(errno));
            free_proxy(proxy);
            free_tunnel(tun);
            goto end;
        }

        goto end;
    }
    if (n == 0) {
        LOG(InfoLog, "proxy connection with %s:%d closed",
            tun->host.hostname, tun->host.port);
        free_proxy(proxy);
        free_tunnel(tun);
        goto end;
    }

    proxy->len += n;
    LOG(DebugLog, "recv from proxy server, n:%d, len:%zu", n, proxy->len);

    /* translate data to client */

again_2:
    len = proxy->len;
    n = send(tun->fd, proxy->buf, len, 0);
    if (n < 0) {
        if (EINTR == errno) {
            goto again_2;
        } else if (EAGAIN == errno || EWOULDBLOCK == errno) {
            /* send buffer is full */
            event_del(&proxy->ev_read);
            event_add(&tun->ev_write, NULL);

            proxy->wptr = proxy->buf;
            goto end;
        }

        LOG(WarnLog, "send data to client error, %s", strerror(errno));
        free_tunnel(tun);
        free_proxy(tun->proxy);
        goto end;
    }

    if (n != len) {
        event_del(&proxy->ev_read);
        event_add(&tun->ev_write, NULL);

        proxy->wptr = proxy->buf + n;
        goto end;
    }

    proxy->len = 0;
end:
    clear_thread_env();
}

static void proxy_send_cb(evutil_socket_t fd, short event, void *arg)
{
    http_proxy_t *proxy = (http_proxy_t *)arg;
    http_tunnel_t *tun = proxy->tun;

    assert(tun && "proxy_send_cb: tunnel is null");

    set_tunnel_env(tun);

    if (proxy->connected) {
        int len, n;

        assert(tun->wptr && "proxy_send_cb: tun->wptr != NULL");
  again:
        len = tun->buf + tun->len - tun->wptr;
        n = send(proxy->fd, tun->wptr, len, 0);
        if (n < 0) {
            if (EINTR == errno) {
                goto again;
            } else if (EAGAIN == errno || EWOULDBLOCK == errno) {
                goto end;
            }

            LOG(WarnLog, "send data to proxy server error(in callback), %s", strerror(errno));
            free_proxy(proxy);
            free_tunnel(tun);
            goto end;
        }

        if (n != len) {
            tun->wptr += n;
            goto end;
        }

        event_del(&proxy->ev_write);
        event_add(&tun->ev_read, &tun->timeout);
        tun->wptr = NULL;
        tun->len = 0;
    } else {
        int err = 0;
        socklen_t errlen = sizeof(int);
        if (EV_TIMEOUT == event) {
            LOG(InfoLog, "connect to %s timeout, shutdown tunnel",
                tun->host.hostname);
            free_proxy(proxy);
            free_tunnel(tun);
            goto end;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
            LOG(InfoLog, "connect to %s:%d error, reason:%s",
                tun->host.hostname, tun->host.port, strerror(err));
            free_proxy(tun->proxy);
            free_tunnel(tun);
            goto end;
        }

        proxy->connected = TRUE;
        event_add(&tun->ev_read, &tun->timeout); /* begin to recv from client */
        if (reply_estab_msg(tun) < 0) {
            LOG(ErrLog, "reply established message error, shutdown proxy with %s",
                tun->host.hostname);
            free_proxy(proxy);
            free_tunnel(tun);
            goto end;
        }

        event_del(&proxy->ev_write);
        event_add(&proxy->ev_read, NULL);
        LOG(DebugLog, "step 4. async connected to %s:%d", tun->host.hostname, tun->host.port);
    }

end:
    clear_thread_env();
}

int main(int argc, char *argv[])
{
    struct event_base *evbase = event_base_new();
    struct evdns_base *evdns = evdns_base_new(evbase, 0);
    struct event evsig;
    server_t *server;
    int r;

    evsignal_assign(&evsig, evbase, SIGPIPE, signal_cb, &evsig);
    evsignal_add(&evsig, NULL);

    r = evdns_base_resolv_conf_parse(evdns, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
    if (r < 0) {
        LOG(ErrLog, "Couldn't configure nameservers");
        goto err_1;
    }

    server = new_server(evbase, evdns, 8081);
    if (!server) {
        goto err_1;
    }

    event_base_dispatch(evbase);
    free_server(server);

err_1:
    event_base_free(evbase);
    exit(0);
}
