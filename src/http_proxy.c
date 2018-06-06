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

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#define DebugLog 1
#define InfoLog  2
#define WarnLog  3
#define ErrLog   4

#define LOG(lv, fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define MAX_HEADER 512
#define HOSTNAME_SIZE 256
#define MAX_BUF 4096
#define BOOL  int
#define TRUE  1
#define FALSE 0

#define CONNECTION_RESPONSE "HTTP/1.0 200 Connection established"

typedef struct server_s server_t;
typedef struct http_tunnel_s http_tunnel_t;
typedef struct http_proxy_s http_proxy_t;

typedef struct hostname_s hostname_t;
struct hostname_s
{
    char hostname[HOSTNAME_SIZE];
    int port;
};

struct server_s
{
    int fd;

    struct event ev_accept;
    struct event_base *evbase;
    struct evdns_base *evdns;
};

struct http_tunnel_s
{
    int fd;

    BOOL http_connected;
    char header[MAX_HEADER + 1];
    int header_len;
    hostname_t host;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    server_t *server;

    struct evdns_getaddrinfo_request *dnsreq;
    http_proxy_t *proxy;

    char buf[MAX_BUF];
    size_t len;
};

struct http_proxy_s
{
    int fd;
    BOOL connected;

    struct timeval timeout;

    struct event ev_read;
    struct event ev_write;

    http_tunnel_t *tun;

    char buf[MAX_BUF];
    size_t len;
};

static void accept_cb(evutil_socket_t fd, short event, void *arg);

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
    if (s < 0)
        return -1;

    if (fcntl(fd, F_SETFL, s|O_NONBLOCK) < 0)
        return -1;

    return 0;
}

static server_t *new_server(struct event_base *evbase, struct evdns_base *evdns, int port)
{
    server_t *s;
    int fd;
    int opt;
    struct sockaddr_in bindaddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        LOG(WarnLog, "create server failed. %s", strerror(errno));
        return NULL;
    }
    if (set_nonblock(fd) < 0)
    {
        LOG(WarnLog, "create server failed. %s", strerror(errno));
        goto err_1;
    }

    opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = htons(port);
    bindaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (const struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0)
    {
        LOG(WarnLog, "create server failed. bind addr failed, %s", strerror(errno));
        goto err_1;
    }
    if (listen(fd, 5) < 0)
    {
        LOG(WarnLog, "create server failed. listen failed, %s", strerror(errno));
        goto err_1;
    }

    s = (server_t *)malloc(sizeof(server_t));
    if (!s)
    {
        goto err_1;
    }
    s->fd = fd;
    s->evbase = evbase;
    s->evdns = evdns;

    event_assign(&s->ev_accept, evbase, fd, EV_READ|EV_PERSIST, accept_cb, s);
    event_add(&s->ev_accept, NULL);

    return s;

err_1:
    if (fd >= 0)
        close(fd);

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

    if (clifd < 0)
    {
        LOG(WarnLog, "accept client failed, %s", strerror(errno));
        return;
    }
    if (set_nonblock(clifd) < 0)
    {
        goto err_1;
    }

    if (!(tun = new_tunnel(s, clifd)))
    {
        LOG(WarnLog, "accpet client failed, create tunnel error");
        goto err_1;
    }

    return;

err_1:
    if (clifd >= 0)
        close(clifd);
}

static http_tunnel_t *new_tunnel(server_t *s, int fd)
{
    http_tunnel_t *tun;

    tun = (http_tunnel_t *)malloc(sizeof(http_tunnel_t));
    if (!tun)
    {
        LOG(WarnLog, "create tunnel failed. no enough memory");
        return NULL;
    }

    tun->fd = fd;
    tun->http_connected = FALSE;
    tun->header_len = 0;
    tun->server = s;

    tun->dnsreq = NULL;
    tun->proxy = NULL;
    tun->len = 0;

    memset(&tun->host, 0, sizeof(tun->host));

    tun->timeout.tv_sec = 3;
    tun->timeout.tv_usec = 0;

    event_assign(&tun->ev_read, s->evbase, fd, EV_READ|EV_PERSIST, tunnel_recv_cb, tun);
    event_assign(&tun->ev_write, s->evbase, fd, EV_WRITE|EV_PERSIST, tunnel_send_cb, tun);
    event_add(&tun->ev_read, &tun->timeout);

    return tun;
}

static void free_tunnel(http_tunnel_t *tun)
{
    if (tun)
    {
        if (tun->dnsreq)
            evdns_getaddrinfo_cancel(tun->dnsreq);

        event_del(&tun->ev_read);
        event_del(&tun->ev_write);
        if (tun->fd >= 0)
            close(tun->fd);

        free(tun);
    }
}

enum EParseRet
{
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
    if (!ptr)
        return ParseRet_Again;

    ptr = strstr(tun->header, "Host:");
    if (!ptr)
    {
        LOG(InfoLog, "parse http header error, header:\n%s", tun->header);
        return ParseRet_Error;
    }
    ptr += 5;
    while (isspace(*ptr)) ptr++;
    end_ptr = strstr(ptr, "\r\n");
    assert(end_ptr);

    if (end_ptr - ptr > sizeof(tun->host.hostname) - 1)
    {
        LOG(WarnLog, "hostname too long, header:\n%s", tun->header);
        return ParseRet_Error;
    }

    wptr = tun->host.hostname;
    for (i = 0; !isspace(*(ptr + i)) && *(ptr + i) != ':'; i++)
        *wptr++ = *(ptr + i);
    *wptr = '\0';
    tun->host.port = 80;
    if ((ptr = strchr(ptr, ':')))
    {
        ptr += 1;
        sscanf(ptr, "%d", &tun->host.port);
        if (tun->host.port < 0)
            tun->host.port = 0;
    }

    return ParseRet_Succuss;
}

static void tunnel_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    http_tunnel_t *tun = (http_tunnel_t *)arg;
    struct evutil_addrinfo hints;
    struct evdns_getaddrinfo_request *dnsreq;
    int n;
    enum EParseRet rparse;

    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "http tunnel timeout");
        free_tunnel(tun);
        return;
    }

    /* build http proxy tunnel */
    if (!tun->http_connected)
    {
  again_1:
        n = recv(tun->fd, tun->header + tun->header_len, MAX_HEADER - tun->header_len, 0);

        if (n < 0)
        {
            if (EINTR == errno)
            {
                goto again_1;
            }
            else if (errno != EWOULDBLOCK && errno != EAGAIN)
            {
                LOG(InfoLog, "read http tunnel(connecting) failed, %s", strerror(errno));
                free_tunnel(tun);
                return;
            }

            return;
        }
        if (n == 0)
        {
            LOG(InfoLog, "http tunnel closed");
            free_tunnel(tun);
            return;
        }

        tun->header[n] = '\0';
        rparse = parse_header(tun);
        if (ParseRet_Error == rparse)
        {
            free_tunnel(tun);
            return;
        }
        if (ParseRet_Again == rparse)
        {
            if (tun->header_len == MAX_HEADER)
            {
                LOG(WarnLog, "no enough space to store http header");
                free_tunnel(tun);
                return;
            }
            return;
        }

        // event_del(&tun->ev_read);
        tun->http_connected = TRUE;
        LOG(DebugLog, "Host: %s:%d", tun->host.hostname, tun->host.port);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = EVUTIL_AI_CANONNAME;
        dnsreq = evdns_getaddrinfo(tun->server->evdns, tun->host.hostname, NULL, &hints, resolv_cb, tun);

        if (dnsreq)
            tun->dnsreq = dnsreq;

        return;
    }

    /* translate message to proxy connection */
    if (!tun->proxy)
    {
        LOG(ErrLog, "proxy connection with %s:%d is not ready", tun->host.hostname, tun->host.port);
        free_tunnel(tun);
        return;
    }

again_2:
    n = recv(tun->fd, tun->buf + tun->len, sizeof(tun->buf) - tun->len, 0);

    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again_2;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(InfoLog, "read http tunnel with proxy %s:%d failed, %s",
                tun->host.hostname, tun->host.port, strerror(errno));
            free_proxy(tun->proxy);
            free_tunnel(tun);
            return;
        }

        return;
    }
    if (n == 0)
    {
        LOG(InfoLog, "http tunnel with proxy connected to %s:%d closed",
            tun->host.hostname, tun->host.port);
        free_proxy(tun->proxy);
        free_tunnel(tun);
        return;
    }

    tun->len += n;
    send(tun->proxy->fd, tun->buf, tun->len, 0);
    tun->len = 0;
}

static void tunnel_send_cb(evutil_socket_t fd, short event, void *arg)
{}

static void resolv_cb(int err, struct evutil_addrinfo *ai, void *arg)
{
    http_tunnel_t *tun = (http_tunnel_t *)arg;
    int i;

    tun->dnsreq = NULL;
    if (err)
    {
        goto err_1;
    }

    for (i = 0; ai; ai = ai->ai_next, ++i)
    {
        char buf[128];

        if (ai->ai_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));

            LOG(DebugLog, "resolve %s -> %s, now create proxy to %s", tun->host.hostname, buf, buf);

            tun->proxy = new_proxy(tun, (const struct sockaddr *)sin, sizeof(struct sockaddr_in));
            if (!tun->proxy)
            {
                LOG(ErrLog, "create proxy to %s failed", buf);
                return;
            }
            if (tun->proxy->connected && reply_estab_msg(tun) < 0)
            {
                LOG(ErrLog, "reply established message failed, shutdown tunnel");
                free_proxy(tun->proxy);
                free_tunnel(tun);
                return;
            }

            if (tun->proxy->connected)
            {
                LOG(DebugLog, "create proxy succuss, proxy is connected");
            }
            else
            {
                LOG(DebugLog, "create proxy succuss, proxy is connecting");
            }

            return;
        }
    }

err_1:
    LOG(InfoLog, "resolve '%s' failed, %s", tun->host.hostname, evutil_gai_strerror(err));
    free_tunnel(tun);
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

    if ((r = send(tun->fd, msg, n, 0)) != n)
    {
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
    if (fd < 0)
    {
        LOG(WarnLog, "create proxy socket failed, %s", strerror(errno));
        return NULL;
    }
    if (set_nonblock(fd) < 0)
    {
        LOG(WarnLog, "set nonblock for proxy socket failed, %s", strerror(errno));
        goto err_1;
    }

    proxy = (http_proxy_t *)malloc(sizeof(http_proxy_t));
    if (!proxy)
    {
        LOG(ErrLog, "create proxy failed, no enough memory");
        goto err_1;
    }

    proxy->fd = fd;
    proxy->connected = FALSE;
    proxy->tun = tun;
    proxy->timeout.tv_sec = 3;
    proxy->timeout.tv_usec = 0;

    event_assign(&proxy->ev_read, tun->server->evbase, fd, EV_READ|EV_PERSIST, proxy_recv_cb, proxy);
    event_assign(&proxy->ev_write, tun->server->evbase, fd, EV_WRITE|EV_PERSIST, proxy_send_cb, proxy);

again:
    if (connect(fd, addr, addrlen) < 0)
    {
        if (EINTR == errno)
        {
            goto again;
        }
        else if (EINPROGRESS == errno)
        {
            event_add(&proxy->ev_write, &proxy->timeout);
        }
        else
        {
            LOG(ErrLog, "create proxy error, connect failed, reason:%s", strerror(errno));
            goto err_2;
        }
    }
    else
    {
        event_add(&proxy->ev_read, NULL);
        proxy->connected = TRUE;
    }

    return proxy;

err_2:
    if (proxy)
        free(proxy);

err_1:
    if (fd >= 0)
        close(fd);

    return NULL;
}

static void free_proxy(http_proxy_t *proxy)
{
    if (proxy)
    {
        proxy->connected = FALSE;

        event_del(&proxy->ev_read);
        event_del(&proxy->ev_write);
        if (proxy->fd >= 0)
            close(proxy->fd);

        free(proxy);
    }
}

static void proxy_recv_cb(evutil_socket_t fd, short event, void *arg)
{
    http_proxy_t *proxy = (http_proxy_t *)arg;
    http_tunnel_t *tun = proxy->tun;
    int n;

    assert(tun && "proxy_recv_cb tunnel is null");
    if (EV_TIMEOUT == event)
    {
        LOG(DebugLog, "proxy connection with %s:%d timeout", tun->host.hostname, tun->host.port);
        free_proxy(proxy);
        free_tunnel(tun);
        return;
    }

    /* recv from remote server and translate to client(by the http tunnel) */
again:
    n = recv(proxy->fd, proxy->buf + proxy->len, sizeof(proxy->buf) - proxy->len, 0);

    if (n < 0)
    {
        if (EINTR == errno)
        {
            goto again;
        }
        else if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            LOG(InfoLog, "read proxy connection with %s:%d failed, %s",
                tun->host.hostname, tun->host.port, strerror(errno));
            free_proxy(proxy);
            free_tunnel(tun);
            return;
        }

        return;
    }
    if (n == 0)
    {
        LOG(InfoLog, "proxy connection with %s:%d closed", tun->host.hostname, tun->host.port);
        free_proxy(proxy);
        free_tunnel(tun);
        return;
    }

    proxy->len += n;
    send(tun->fd, proxy->buf, proxy->len, proxy->len);
    proxy->len = 0;
}

static void proxy_send_cb(evutil_socket_t fd, short event, void *arg)
{
    http_proxy_t *proxy = (http_proxy_t *)arg;
    http_tunnel_t *tun = proxy->tun;

    assert(tun && "proxy_send_cb tunnel is null");
    if (EV_TIMEOUT == event)
    {
        LOG(InfoLog, "connect to %s timeout, shutdown tunnel", tun->host.hostname);
        free_proxy(proxy);
        free_tunnel(tun);
        return;
    }

    int err = 0;
    socklen_t errlen = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
    {
        LOG(ErrLog, "connect to %s error, %s", tun->host.hostname, strerror(err));
        free_proxy(tun->proxy);
        free_tunnel(tun);
        return;
    }

    proxy->connected = TRUE;
    if (reply_estab_msg(tun) < 0)
    {
        LOG(ErrLog, "reply established message error, shutdown proxy with %s", tun->host.hostname);
        free_proxy(proxy);
        free_tunnel(tun);
        return;
    }

    event_del(&proxy->ev_write);
    event_add(&proxy->ev_read, NULL);
    LOG(DebugLog, "connect to %s success, established message sended", tun->host.hostname);
}

int main(int argc, char *argv[])
{
    struct event_base *evbase = event_base_new();
    struct evdns_base *evdns = evdns_base_new(evbase, 1);
    server_t *server;

    server = new_server(evbase, evdns, 8080);
    if (!server)
    {
        goto err_1;
    }

    event_base_dispatch(evbase);

    free_server(server);

err_1:
    event_base_free(evbase);

    exit(0);
}
