/*
 * vndsm - minimal vndservicemanager for a2corelte (kernel with 32-bit binder ABI)
 *
 * Why: the stock vendor /vendor/bin/vndservicemanager talks the 64-bit binder ABI
 * (protocol 8, ioctl 0xc0306201). The a2corelte kernel is CONFIG_ANDROID_BINDER_IPC_32BIT=y
 * (protocol 7, ioctl 0xc0186201), so the stock binary fails its version check, logs
 * "failed to open binder driver /dev/vndbinder" and sleeps forever. Nothing then owns
 * /dev/vndbinder and every vendor HAL blocks in defaultServiceManager().
 *
 * This is a small re-implementation of the AOSP servicemanager protocol:
 *   PING / GET_SERVICE / CHECK_SERVICE / ADD_SERVICE / LIST_SERVICES + death notifications.
 * Static, no libselinux, no permission checks (SELinux still guards the device node).
 *
 * usage: vndservicemanager [/dev/vndbinder]     (also: --selftest)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/ioctl.h>

/* ---- binder ABI: bptr_t is 32 bit on the target (32-bit binder ABI), 64 bit only for host tests ---- */
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4
typedef uint32_t bptr_t;
#define BINDER_PROTO 7
#else
typedef uint64_t bptr_t;          /* host-only build used for testing */
#define BINDER_PROTO 8
#endif

struct bwr { bptr_t write_size, write_consumed, write_buffer, read_size, read_consumed, read_buffer; };
struct btd {
    union { uint32_t handle; bptr_t ptr; } target;
    bptr_t cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    bptr_t data_size, offsets_size;
    bptr_t buffer, offsets;
};
struct bobj { uint32_t type; uint32_t flags; union { bptr_t binder; uint32_t handle; } u; bptr_t cookie; };
struct bptrcookie { bptr_t ptr, cookie; };
struct bhandlecookie { uint32_t handle; bptr_t cookie; } __attribute__((packed));
struct bver { int32_t protocol_version; };

#if BINDER_PROTO == 7
_Static_assert(sizeof(struct bwr) == 24, "bwr must be 24 bytes (0xc0186201)");
_Static_assert(sizeof(struct btd) == 40, "btd must be 40 bytes");
_Static_assert(sizeof(struct bobj) == 16, "bobj must be 16 bytes");
#endif

#define BINDER_WRITE_READ        _IOWR('b', 1, struct bwr)
#define BINDER_SET_CONTEXT_MGR   _IOW('b', 7, int32_t)
#define BINDER_VERSION           _IOWR('b', 9, struct bver)

#define BR_NOOP                  _IO('r', 12)
#define BR_TRANSACTION_COMPLETE  _IO('r', 6)
#define BR_TRANSACTION           _IOR('r', 2, struct btd)
#define BR_REPLY                 _IOR('r', 3, struct btd)
#define BR_DEAD_REPLY            _IO('r', 5)
#define BR_FAILED_REPLY          _IO('r', 17)
#define BR_INCREFS               _IOR('r', 7, struct bptrcookie)
#define BR_ACQUIRE               _IOR('r', 8, struct bptrcookie)
#define BR_RELEASE               _IOR('r', 9, struct bptrcookie)
#define BR_DECREFS               _IOR('r', 10, struct bptrcookie)
#define BR_SPAWN_LOOPER          _IO('r', 13)
#define BR_DEAD_BINDER           _IOR('r', 15, bptr_t)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOR('r', 16, bptr_t)

#define BC_TRANSACTION           _IOW('c', 0, struct btd)
#define BC_REPLY                 _IOW('c', 1, struct btd)
#define BC_FREE_BUFFER           _IOW('c', 3, bptr_t)
#define BC_INCREFS               _IOW('c', 4, uint32_t)
#define BC_ACQUIRE               _IOW('c', 5, uint32_t)
#define BC_RELEASE               _IOW('c', 6, uint32_t)
#define BC_DECREFS               _IOW('c', 7, uint32_t)
#define BC_ENTER_LOOPER          _IO('c', 12)
#define BC_REQUEST_DEATH_NOTIFICATION _IOW('c', 14, struct bhandlecookie)
#define BC_DEAD_BINDER_DONE      _IOW('c', 16, bptr_t)

#define TF_ONE_WAY     0x01
#define TF_STATUS_CODE 0x08
#define BINDER_TYPE_BINDER 0x73622a85u   /* 'sb*\x85' */
#define BINDER_TYPE_HANDLE 0x73682a85u   /* 'sh*\x85' */
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100
#define PING_TRANSACTION 0x5f504e47u     /* '_PNG' */

/* ---- logging ---- */
static int kmsg_fd = -2;
static void klog(const char *fmt, ...) {
    char buf[256]; int n = snprintf(buf, sizeof(buf), "<6>vndsm: ");
    va_list ap; va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
    va_end(ap);
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    if (kmsg_fd == -2) kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (kmsg_fd >= 0) { if (write(kmsg_fd, buf, n) < 0) { /* ignore */ } }
    fprintf(stderr, "%s\n", buf + 3);
}

/* ---- binder io ---- */
struct binder_state { int fd; void *mapped; size_t mapsize; };
#define BIO_F_OVERFLOW 0x2
struct bio { char *data; bptr_t *offs; size_t data_avail, offs_avail; char *data0; bptr_t *offs0; uint32_t flags; };

static void bio_init(struct bio *b, void *data, size_t maxdata, size_t maxoffs) {
    size_t n = maxoffs * sizeof(bptr_t);
    if (n > maxdata) { b->flags = BIO_F_OVERFLOW; b->data_avail = 0; b->offs_avail = 0; return; }
    b->data = b->data0 = (char *)data + n;
    b->offs = b->offs0 = (bptr_t *)data;
    b->data_avail = maxdata - n; b->offs_avail = maxoffs; b->flags = 0;
}
static void bio_init_from_txn(struct bio *b, const struct btd *t) {
    b->data = b->data0 = (char *)(uintptr_t)t->buffer;
    b->offs = b->offs0 = (bptr_t *)(uintptr_t)t->offsets;
    b->data_avail = t->data_size;
    b->offs_avail = t->offsets_size / sizeof(bptr_t);
    b->flags = 0;
}
static void *bio_alloc(struct bio *b, size_t size) {
    size = (size + 3) & ~(size_t)3;
    if (size > b->data_avail) { b->flags |= BIO_F_OVERFLOW; return NULL; }
    void *p = b->data; b->data += size; b->data_avail -= size; return p;
}
static void *bio_get(struct bio *b, size_t size) {
    size = (size + 3) & ~(size_t)3;
    if (b->data_avail < size) { b->data_avail = 0; b->flags |= BIO_F_OVERFLOW; return NULL; }
    void *p = b->data; b->data += size; b->data_avail -= size; return p;
}
static uint32_t bio_get_uint32(struct bio *b) {
    uint32_t *p = bio_get(b, sizeof(uint32_t)); return p ? *p : 0;
}
static int bio_peek_uint32(struct bio *b, uint32_t *v) {
    if (b->data_avail < sizeof(uint32_t)) return -1;
    memcpy(v, b->data, sizeof(*v)); return 0;
}
static uint16_t *bio_get_string16(struct bio *b, size_t *sz) {
    uint32_t len = bio_get_uint32(b);
    if (len == 0xffffffffu || len > 4096) { b->flags |= BIO_F_OVERFLOW; if (sz) *sz = 0; return NULL; }
    if (sz) *sz = len;
    return bio_get(b, (len + 1) * sizeof(uint16_t));
}
static struct bobj *bio_get_obj(struct bio *b) {
    size_t off = b->data - b->data0;
    for (size_t n = 0; n < b->offs_avail; n++)
        if (b->offs[n] == off) return bio_get(b, sizeof(struct bobj));
    b->data_avail = 0; b->flags |= BIO_F_OVERFLOW; return NULL;
}
static uint32_t bio_get_ref(struct bio *b) {
    struct bobj *o = bio_get_obj(b);
    if (!o) return 0;
    return o->type == BINDER_TYPE_HANDLE ? o->u.handle : 0;
}
static void bio_put_uint32(struct bio *b, uint32_t v) {
    uint32_t *p = bio_alloc(b, sizeof(v)); if (p) *p = v;
}
static void bio_put_ref(struct bio *b, uint32_t handle) {
    struct bobj *o = bio_alloc(b, sizeof(*o));
    if (o && b->offs_avail) {
        b->offs_avail--; *b->offs++ = (bptr_t)((char *)o - b->data0);
        memset(o, 0, sizeof(*o));
        o->type = handle ? BINDER_TYPE_HANDLE : BINDER_TYPE_BINDER;
        o->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
        o->u.handle = handle;
        return;
    }
    b->flags |= BIO_F_OVERFLOW;
}
static void bio_put_string16(struct bio *b, const uint16_t *s, size_t len) {
    bio_put_uint32(b, (uint32_t)len);
    uint16_t *p = bio_alloc(b, (len + 1) * sizeof(uint16_t));
    if (p) { memcpy(p, s, len * sizeof(uint16_t)); p[len] = 0; }
}

/* ---- binder driver ---- */
static int binder_write(struct binder_state *bs, void *data, size_t len) {
    struct bwr w; memset(&w, 0, sizeof(w));
    w.write_size = (bptr_t)len; w.write_buffer = (bptr_t)(uintptr_t)data;
    return ioctl(bs->fd, BINDER_WRITE_READ, &w);
}
static void binder_free_buffer(struct binder_state *bs, bptr_t buf) {
    struct { uint32_t cmd; bptr_t buffer; } __attribute__((packed)) d = { BC_FREE_BUFFER, buf };
    binder_write(bs, &d, sizeof(d));
}
static void binder_send_reply(struct binder_state *bs, struct bio *reply, bptr_t buf_to_free, int status) {
    struct { uint32_t cmd_free; bptr_t buffer; uint32_t cmd_reply; struct btd txn; } __attribute__((packed)) d;
    memset(&d, 0, sizeof(d));
    d.cmd_free = BC_FREE_BUFFER; d.buffer = buf_to_free; d.cmd_reply = BC_REPLY;
    if (status) {
        d.txn.flags = TF_STATUS_CODE; d.txn.data_size = sizeof(int);
        d.txn.buffer = (bptr_t)(uintptr_t)&status;
    } else {
        d.txn.data_size = (bptr_t)(reply->data - reply->data0);
        d.txn.offsets_size = (bptr_t)((char *)reply->offs - (char *)reply->offs0);
        d.txn.buffer = (bptr_t)(uintptr_t)reply->data0;
        d.txn.offsets = (bptr_t)(uintptr_t)reply->offs0;
    }
    binder_write(bs, &d, sizeof(d));
}
static void binder_acquire(struct binder_state *bs, uint32_t h) { uint32_t c[2] = { BC_ACQUIRE, h }; binder_write(bs, c, sizeof(c)); }
static void binder_release(struct binder_state *bs, uint32_t h) { uint32_t c[2] = { BC_RELEASE, h }; binder_write(bs, c, sizeof(c)); }
static void binder_link_to_death(struct binder_state *bs, uint32_t h, bptr_t cookie) {
    struct { uint32_t cmd; struct bhandlecookie p; } __attribute__((packed)) d;
    d.cmd = BC_REQUEST_DEATH_NOTIFICATION; d.p.handle = h; d.p.cookie = cookie;
    binder_write(bs, &d, sizeof(d));
}
static struct binder_state *binder_open(const char *driver, size_t mapsize) {
    struct binder_state *bs = calloc(1, sizeof(*bs));
    if (!bs) return NULL;
    bs->fd = open(driver, O_RDWR | O_CLOEXEC);
    if (bs->fd < 0) { klog("cannot open %s: %s", driver, strerror(errno)); goto fail; }
    struct bver v;
    if (ioctl(bs->fd, BINDER_VERSION, &v) == -1) { klog("BINDER_VERSION ioctl failed: %s", strerror(errno)); goto fail; }
    if (v.protocol_version != BINDER_PROTO) {
        klog("kernel binder protocol %d != expected %d", v.protocol_version, BINDER_PROTO); goto fail;
    }
    bs->mapsize = mapsize;
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) { klog("cannot mmap %s: %s", driver, strerror(errno)); goto fail; }
    klog("opened %s, binder protocol %d", driver, v.protocol_version);
    return bs;
fail:
    if (bs->fd >= 0) close(bs->fd);
    free(bs); return NULL;
}

/* ---- service registry ---- */
struct svcinfo { struct svcinfo *next; uint32_t handle; int allow_isolated; size_t len; uint16_t name[]; };
static struct svcinfo *svclist;

static void name8(char *out, size_t outsz, const uint16_t *s, size_t len) {
    size_t i; for (i = 0; i < len && i + 1 < outsz; i++) out[i] = (char)s[i]; out[i] = 0;
}
static struct svcinfo *find_svc(const uint16_t *s, size_t len) {
    for (struct svcinfo *si = svclist; si; si = si->next)
        if (si->len == len && !memcmp(si->name, s, len * sizeof(uint16_t))) return si;
    return NULL;
}
static void svcinfo_death(struct binder_state *bs, struct svcinfo *si) {
    if (si->handle) { binder_release(bs, si->handle); si->handle = 0; }
}
static int do_add_service(struct binder_state *bs, const uint16_t *s, size_t len, uint32_t handle, uint32_t uid, int allow_isolated) {
    char nm[130]; name8(nm, sizeof(nm), s, len);
    if (!handle || len == 0 || len > 127) { klog("add '%s' uid=%u rejected (handle=%u len=%zu)", nm, uid, handle, len); return -1; }
    struct svcinfo *si = find_svc(s, len);
    if (si) {
        if (si->handle) svcinfo_death(bs, si);
        si->handle = handle;
    } else {
        si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t));
        if (!si) return -1;
        si->handle = handle; si->len = len; si->allow_isolated = allow_isolated;
        memcpy(si->name, s, len * sizeof(uint16_t)); si->name[len] = 0;
        si->next = svclist; svclist = si;
    }
    binder_acquire(bs, handle);
    binder_link_to_death(bs, handle, (bptr_t)(uintptr_t)si);
    klog("registered '%s' handle=%u uid=%u", nm, handle, uid);
    return 0;
}

static const uint16_t svcmgr_id[] = { 'a','n','d','r','o','i','d','.','o','s','.','I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' };
#define SVCMGR_ID_LEN (sizeof(svcmgr_id) / sizeof(svcmgr_id[0]))

static int svcmgr_handler(struct binder_state *bs, struct btd *txn, struct bio *msg, struct bio *reply) {
    if (txn->target.ptr != 0) return -1;
    if (txn->code == PING_TRANSACTION) return 0;

    (void)bio_get_uint32(msg);                 /* strict mode policy */
    uint32_t next;                             /* Android 10+ clients add a worksource int32 here, Oreo clients do not */
    if (bio_peek_uint32(msg, &next) == 0 && next != SVCMGR_ID_LEN) (void)bio_get_uint32(msg);

    size_t len; uint16_t *s = bio_get_string16(msg, &len);
    if (!s || len != SVCMGR_ID_LEN || memcmp(svcmgr_id, s, sizeof(svcmgr_id))) return -1;

    switch (txn->code) {
    case 1: /* GET_SERVICE */
    case 2: { /* CHECK_SERVICE */
        s = bio_get_string16(msg, &len);
        if (!s) return -1;
        struct svcinfo *si = find_svc(s, len);
        if (si && si->handle) { bio_put_ref(reply, si->handle); return 0; }
        return 0;                              /* not found -> null binder, like AOSP */
    }
    case 3: { /* ADD_SERVICE */
        s = bio_get_string16(msg, &len);
        if (!s) return -1;
        uint32_t handle = bio_get_ref(msg);
        int allow_isolated = bio_get_uint32(msg) ? 1 : 0;
        if (do_add_service(bs, s, len, handle, txn->sender_euid, allow_isolated)) return -1;
        break;
    }
    case 4: { /* LIST_SERVICES */
        uint32_t n = bio_get_uint32(msg);
        struct svcinfo *si = svclist;
        while (n-- > 0 && si) si = si->next;
        if (si) { bio_put_string16(reply, si->name, si->len); return 0; }
        return -1;
    }
    default:
        return -1;
    }
    bio_put_uint32(reply, 0);
    return 0;
}

/* ---- parse / loop ---- */
static int binder_parse(struct binder_state *bs, uintptr_t ptr, size_t size) {
    uintptr_t end = ptr + size;
    while (ptr < end) {
        uint32_t cmd; memcpy(&cmd, (void *)ptr, sizeof(cmd)); ptr += sizeof(cmd);
        if (cmd == BR_NOOP || cmd == BR_TRANSACTION_COMPLETE || cmd == BR_SPAWN_LOOPER) continue;
        if (cmd == BR_INCREFS || cmd == BR_ACQUIRE || cmd == BR_RELEASE || cmd == BR_DECREFS) { ptr += sizeof(struct bptrcookie); continue; }
        if (cmd == BR_TRANSACTION) {
            if (end - ptr < sizeof(struct btd)) return -1;
            struct btd txn; memcpy(&txn, (void *)ptr, sizeof(txn));
            uint32_t rdata[256 / 4];
            struct bio msg, reply;
            bio_init(&reply, rdata, sizeof(rdata), 4);
            bio_init_from_txn(&msg, &txn);
            int res = svcmgr_handler(bs, &txn, &msg, &reply);
            if (txn.flags & TF_ONE_WAY) binder_free_buffer(bs, txn.buffer);
            else binder_send_reply(bs, &reply, txn.buffer, res);
            ptr += sizeof(txn); continue;
        }
        if (cmd == BR_REPLY) { struct btd t; memcpy(&t, (void *)ptr, sizeof(t)); binder_free_buffer(bs, t.buffer); ptr += sizeof(t); continue; }
        if (cmd == BR_DEAD_BINDER) {
            bptr_t cookie; memcpy(&cookie, (void *)ptr, sizeof(cookie)); ptr += sizeof(cookie);
            struct svcinfo *si = (struct svcinfo *)(uintptr_t)cookie;
            svcinfo_death(bs, si);
            struct { uint32_t cmd; bptr_t cookie; } __attribute__((packed)) d = { BC_DEAD_BINDER_DONE, cookie };
            binder_write(bs, &d, sizeof(d));
            continue;
        }
        if (cmd == BR_CLEAR_DEATH_NOTIFICATION_DONE) { ptr += sizeof(bptr_t); continue; }
        if (cmd == BR_DEAD_REPLY || cmd == BR_FAILED_REPLY) continue;
        klog("parse: unknown cmd 0x%x", cmd);
        return -1;
    }
    return 1;
}
static void binder_loop(struct binder_state *bs) {
    uint32_t readbuf[32];
    uint32_t c = BC_ENTER_LOOPER; binder_write(bs, &c, sizeof(c));
    for (;;) {
        struct bwr w; memset(&w, 0, sizeof(w));
        w.read_size = sizeof(readbuf); w.read_buffer = (bptr_t)(uintptr_t)readbuf;
        if (ioctl(bs->fd, BINDER_WRITE_READ, &w) < 0) {
            if (errno == EINTR) continue;
            klog("BINDER_WRITE_READ failed: %s", strerror(errno)); return;
        }
        if (binder_parse(bs, (uintptr_t)readbuf, (size_t)w.read_consumed) < 0) { klog("parse failed"); return; }
    }
}

/* ---- self test (no /dev/vndbinder needed) ---- */
static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "SELFTEST FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)
static void put_str16(struct bio *b, const char *s) {
    size_t n = strlen(s); uint16_t tmp[200]; for (size_t i = 0; i <= n; i++) tmp[i] = (unsigned char)s[i];
    bio_put_string16(b, tmp, n);
}
static int run_txn(struct binder_state *bs, uint32_t code, int q_style, const char *name, uint32_t handle, uint32_t idx, struct bio *reply, uint32_t *rdata) {
    uint32_t buf[128]; struct bio m; bio_init(&m, buf, sizeof(buf), 4);
    bio_put_uint32(&m, 0);                        /* strict mode */
    if (q_style) bio_put_uint32(&m, 0xffffffffu); /* worksource header */
    put_str16(&m, "android.os.IServiceManager");
    if (code == 4) bio_put_uint32(&m, idx);
    else if (name) { put_str16(&m, name); if (code == 3) { bio_put_ref(&m, handle); bio_put_uint32(&m, 0); bio_put_uint32(&m, 0); } }
    struct btd t; memset(&t, 0, sizeof(t));
    t.code = code; t.sender_euid = 1000;
    t.buffer = (bptr_t)(uintptr_t)m.data0; t.data_size = (bptr_t)(m.data - m.data0);
    t.offsets = (bptr_t)(uintptr_t)m.offs0; t.offsets_size = (bptr_t)((char *)m.offs - (char *)m.offs0);
    struct bio in; bio_init_from_txn(&in, &t);
    bio_init(reply, rdata, 256, 4);
    return svcmgr_handler(bs, &t, &in, reply);
}
static int selftest(void) {
    struct binder_state bs = { .fd = -1 };
    uint32_t rd[64]; struct bio r;
    for (int q = 0; q < 2; q++) {
        char nm[40]; snprintf(nm, sizeof(nm), "Exynos.HWCService%d", q);
        CHECK(run_txn(&bs, PING_TRANSACTION, q, NULL, 0, 0, &r, rd) == 0);
        CHECK(run_txn(&bs, 1, q, nm, 0, 0, &r, rd) == 0);              /* get before add: null */
        CHECK(r.offs == r.offs0);
        CHECK(run_txn(&bs, 3, q, nm, 7 + q, 0, &r, rd) == 0);          /* add */
        CHECK(run_txn(&bs, 1, q, nm, 0, 0, &r, rd) == 0);              /* get: handle object */
        CHECK(r.offs == r.offs0 + 1);
        struct bobj *o = (struct bobj *)r.data0;
        CHECK(o->type == BINDER_TYPE_HANDLE && o->u.handle == (uint32_t)(7 + q));
        CHECK(run_txn(&bs, 3, q, "x", 0, 0, &r, rd) == -1);           /* handle 0 rejected */
    }
    CHECK(run_txn(&bs, 4, 0, NULL, 0, 0, &r, rd) == 0);                /* list idx0 */
    CHECK(run_txn(&bs, 4, 0, NULL, 0, 9, &r, rd) == -1);               /* list past end */
    CHECK(run_txn(&bs, 99, 0, "a", 0, 0, &r, rd) == -1);               /* unknown code */
    fprintf(stderr, fails ? "SELFTEST FAILED (%d)\n" : "SELFTEST OK (protocol %d, bptr %zu bytes)\n", fails ? fails : BINDER_PROTO, sizeof(bptr_t));
    return fails ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
    const char *driver = argc > 1 ? argv[1] : "/dev/vndbinder";
    signal(SIGPIPE, SIG_IGN);
    struct binder_state *bs = binder_open(driver, 128 * 1024);
    if (!bs) { klog("giving up (sleeping so init does not respawn-loop)"); for (;;) sleep(3600); }
    if (ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0)) { klog("cannot become context manager: %s", strerror(errno)); for (;;) sleep(3600); }
    klog("context manager on %s", driver);
    binder_loop(bs);
    return 1;
}
