/* SPDX-License-Identifier: GPL-3.0-or-later
 * Ghostpad - PS5 Remote Controller Payload
 *
 * Listens on TCP port 6967 for GhostpadPackets sent from the Python GUI,
 * then injects them as virtual DualSense controller input using the
 * scePadVirtualDevice API.
 *
 * Build with: make
 * Deploy with: make test PS5_HOST=<your ps5 ip>
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

/* BSD/POSIX socket headers (available on FreeBSD-based PS5) */
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* PS5 SDK headers */
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/mdbg.h>

#include "shellui_pad.h"

/* gp_log — thin wrapper around klog_printf (kernel debug log, port 9081) */
#define LOG_MSG_MAX 480

static void gp_log(const char *fmt, ...) {
    char buf[LOG_MSG_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    buf[LOG_MSG_MAX - 1] = '\0';
    klog_printf("%s", buf);
}

/* SCE function declarations — linked via sce_stubs (-lSceUserService -lScePad) */

/* User Service */
extern int32_t sceUserServiceInitialize(void *params);
extern int32_t sceUserServiceTerminate(void);
extern int32_t sceUserServiceGetInitialUser(int32_t *outUserId);
extern int32_t sceUserServiceGetForegroundUser(int32_t *outUserId); /* preferred */

/* Pad Library */
extern int32_t scePadInit(void);
extern int32_t scePadOpen(int32_t userId, int32_t type, int32_t index, void *param);
extern int32_t scePadClose(int32_t handle);
extern int32_t scePadGetHandle(int32_t userId, int32_t type, int32_t index);
extern int32_t scePadSetProcessPrivilege(int32_t privilege);
extern int32_t scePadVirtualDeviceAddDevice(void *param, int32_t deviceType);
/* scePadVertualDeviceAddDevice (typo variant) removed — blocks the IPC daemon indefinitely */
extern int32_t scePadVirtualDeviceDeleteDevice(int32_t handle);
extern int32_t scePadVirtualDeviceInsertData(int32_t handle, const void *padData);

/* Kernel Notification (toast message on PS5 UI) */
extern int32_t sceKernelSendNotificationRequest(int unk0, void *req, size_t size, int unk1);


/* Button bitmask definitions (DualSense / PS5) — must match ghostpad_gui.py */
#define SCE_PAD_BUTTON_L3           0x00000002u
#define SCE_PAD_BUTTON_R3           0x00000004u
#define SCE_PAD_BUTTON_OPTIONS      0x00000008u
#define SCE_PAD_BUTTON_UP           0x00000010u
#define SCE_PAD_BUTTON_RIGHT        0x00000020u
#define SCE_PAD_BUTTON_DOWN         0x00000040u
#define SCE_PAD_BUTTON_LEFT         0x00000080u
#define SCE_PAD_BUTTON_L2           0x00000100u
#define SCE_PAD_BUTTON_R2           0x00000200u
#define SCE_PAD_BUTTON_L1           0x00000400u
#define SCE_PAD_BUTTON_R1           0x00000800u
#define SCE_PAD_BUTTON_TRIANGLE     0x00001000u
#define SCE_PAD_BUTTON_CIRCLE       0x00002000u
#define SCE_PAD_BUTTON_CROSS        0x00004000u
#define SCE_PAD_BUTTON_SQUARE       0x00008000u
#define SCE_PAD_BUTTON_CREATE       0x00010000u  /* PS5: was Share on PS4 */
#define SCE_PAD_BUTTON_PS           0x00020000u
#define SCE_PAD_BUTTON_TOUCH_PAD    0x00100000u

/* ScePadData layout — sourced from ps5-payload-dev/SDL SDL_ps5joystick.h.
 * scePadVirtualDeviceInsertData takes the same struct as scePadReadState. */

typedef struct {
    uint16_t x;
    uint16_t y;
    uint8_t  finger;
    uint8_t  pad[3];
} ScePadTouch;

typedef struct {
    uint8_t    fingers;
    uint8_t    pad1[3];
    uint32_t   pad2;
    ScePadTouch touch[2];
} ScePadTouchData;

typedef struct {
    uint32_t buttons;                        /* offset  0 */
    struct { uint8_t x; uint8_t y; } leftStick;    /* offset  4 */
    struct { uint8_t x; uint8_t y; } rightStick;   /* offset  6 */
    struct { uint8_t l2; uint8_t r2; } analogButtons; /* offset  8 */
    uint16_t    padding;                     /* offset 10 */
    struct { float x, y, z, w; } quat;      /* offset 12: orientation quaternion */
    struct { float x, y, z; }    vel;       /* offset 28: angular velocity */
    struct { float x, y, z; }    accel;     /* offset 40: accelerometer */
    ScePadTouchData touchData;               /* offset 52 */
    uint8_t     connected;                   /* offset 76 */
    uint8_t     _align[3];                   /* offset 77 */
    uint64_t    timestamp;                   /* offset 80 (requires 4-byte gap for 8-byte align) */
    uint8_t     ext[16];                     /* offset 88 (or 84 depending on compiler) */
    uint8_t     count;
    uint8_t     unknown[15];
} ScePadData;

/* Virtual device type: 3 = DualSense (PS5), 0 = DS4-compat fallback */
#define VIRTUAL_DEVICE_TYPE_DUALSENSE  3
#define VIRTUAL_DEVICE_TYPE_DS4COMPAT  0

/* Network packet protocol (shared with Python GUI, ~60 Hz over TCP) */
#define GP_MAGIC      "GPAD"
#define GP_MAGIC_LEN  4
#define GP_PORT       6967
#define GP_CTRL_PORT  6970   /* GBND/HVDI diagnostic control port */

typedef struct __attribute__((packed)) {
    char     magic[4];   /* Must be "GPAD" */
    uint32_t buttons;    /* Button bitmask (same bit layout as SCE_PAD_BUTTON_*) */
    uint8_t  lx;         /* Left stick X  (128=center) */
    uint8_t  ly;         /* Left stick Y  (128=center) */
    uint8_t  rx;         /* Right stick X (128=center) */
    uint8_t  ry;         /* Right stick Y (128=center) */
    uint8_t  l2;         /* L2 analog (0-255) */
    uint8_t  r2;         /* R2 analog (0-255) */
    uint8_t  _pad[2];    /* Reserved, must be 0 */
} GhostpadPacket;

/* Total packet size: 16 bytes */
#define GP_PACKET_SIZE sizeof(GhostpadPacket)

/* GBND: bind command.
 * physicalDevId: currently-connected physical DualSense to evict (0 = skip evict). */
typedef struct __attribute__((packed)) {
    char     magic[4];
    uint32_t userId;
    uint64_t virtualDevId;
    uint64_t physicalDevId;  /* device to sceMbusDisconnect before/after bind */
} GhostpadBindPacket;
#define GP_BIND_PACKET_SIZE sizeof(GhostpadBindPacket)

/* HVDI: handle+VDI test — Python sends the CIM padHandle extracted from klog.
 * Payload calls pt_call VDI(handle, cross_data) in SceShellUI to confirm input. */
typedef struct __attribute__((packed)) {
    char     magic[4];    /* "HVDI" */
    uint32_t padHandle;   /* system padHandle from CIM line */
} GhostpadHvdiPacket;
#define GP_HVDI_PACKET_SIZE sizeof(GhostpadHvdiPacket)

typedef struct __attribute__((packed)) {
    char     magic[4];    /* "TYPE" */
    uint32_t deviceType;  /* libScePad virtual device type */
} GhostpadTypePacket;
#define GP_TYPE_PACKET_SIZE sizeof(GhostpadTypePacket)

/* Notification helper — shows PS5 toast notification */
typedef struct {
    char _unk[45];
    char message[3075];
} NotifyRequest;

static void notify(const char *fmt, ...) {
    NotifyRequest req;
    va_list ap;
    memset(&req, 0, sizeof(req));

    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);

    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* recv_exact — receive exactly n bytes, handling short reads */
static int recv_exact(int fd, void *buf, size_t n) {
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, (char *)buf + received, n - received, 0);
        if (r <= 0) return (int)r;
        received += (size_t)r;
    }
    return (int)received;
}

static void set_recv_timeout_ms(int fd, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Credential elevation — patch ucred authid/caps so scePadInit and VDI succeed.
 * Tries game authid (0x3800000000010003) first; falls back to ptrace authid. */
static void elevate_credentials(void) {
    pid_t mypid = getpid();
    uint8_t privcaps[16] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    int ret;

    /* Try game-process authid (0x3800000000010003) first — game processes can
     * call scePadOpen successfully.  If that still gives IPMI errors, fall back
     * to the ptrace authid (0x4800000000010003).  The pad IPMI service checks
     * the caller's authid against an allow-list; game authid should be on it. */
    ret = kernel_set_ucred_authid(mypid, 0x3800000000010003l);
    gp_log("[Ghostpad] set_ucred_authid(game): %d\n", ret);
    ret = kernel_set_ucred_caps(mypid, privcaps);
    gp_log("[Ghostpad] set_ucred_caps: %d\n", ret);

    ret = scePadInit();
    gp_log("[Ghostpad] scePadInit(game-authid): 0x%08x\n", ret);

    if (ret < 0) {
        /* Fall back to ptrace authid */
        ret = kernel_set_ucred_authid(mypid, 0x4800000000010003l);
        gp_log("[Ghostpad] set_ucred_authid(ptrace): %d\n", ret);
        ret = scePadInit();
        gp_log("[Ghostpad] scePadInit(ptrace-authid): 0x%08x\n", ret);
    }
}

/* Server-side press rate measurement — logs server_cps every 50 presses via klog */
typedef struct {
    uint64_t      presses;       /* packets with buttons != 0 */
    uint64_t      releases;      /* packets with buttons == 0 */
    uint64_t      vdi_ok;        /* VDI calls returning 0     */
    uint64_t      vdi_err;       /* VDI calls returning error */
    uint64_t      vdi_latency_us_total; /* sum of VDI call durations */
    uint64_t      vdi_latency_samples;
    struct timeval start_tv;
    int           started;
} PressStats;

static PressStats g_stats;

static void stats_reset(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

static void stats_record(int is_press, int vdi_ret, uint64_t vdi_us) {
    if (is_press) {
        if (!g_stats.started) {
            gettimeofday(&g_stats.start_tv, NULL);
            g_stats.started = 1;
        }
        g_stats.presses++;
        if (vdi_ret == 0) g_stats.vdi_ok++;
        else              g_stats.vdi_err++;
    } else {
        g_stats.releases++;
    }

    if (vdi_us > 0) {
        g_stats.vdi_latency_us_total += vdi_us;
        g_stats.vdi_latency_samples++;
    }

    /* Log every 50 presses so klog shows server_cps frequently */
    if (is_press && g_stats.presses % 50 == 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        double elapsed = (double)(now.tv_sec  - g_stats.start_tv.tv_sec) +
                         (double)(now.tv_usec - g_stats.start_tv.tv_usec) * 1e-6;
        double cps = (elapsed > 0.0) ? ((double)g_stats.presses / elapsed) : 0.0;
        uint64_t avg_us = (g_stats.vdi_latency_samples > 0)
            ? (g_stats.vdi_latency_us_total / g_stats.vdi_latency_samples) : 0;
        gp_log("[Ghostpad] server_cps: presses=%llu ok=%llu err=%llu "
               "elapsed=%.2fs cps=%.1f vdi_avg_us=%llu\n",
               (unsigned long long)g_stats.presses,
               (unsigned long long)g_stats.vdi_ok,
               (unsigned long long)g_stats.vdi_err,
               elapsed, cps,
               (unsigned long long)avg_us);
    }
}

/* ---- Main ---- */
int main(void) {
    int32_t  userId           = -1;
    int32_t  padHandle        = -1;
    pid_t    shellui_pid      = -1;
    intptr_t shellui_args     = 0;
    int      serverFd         = -1;
    int      ctrlFd           = -1;
    int      clientFd         = -1;
    int      ret;
    /* Acquired via HVDI packet: padHandle from CIM, used for pt_call VDI delivery */
    int32_t  vdi_handle       = -1;
    uint64_t bound_virtual_device_id = 0;
    int32_t  virtual_device_type = VIRTUAL_DEVICE_TYPE_DUALSENSE;
    int      device_vdi_ready = 0;

    /* Notify immediately so we know the payload is running at all.
     * If this notification never appears, the ELF didn't load. */
    notify("Ghostpad: by StonedModder");

    gp_log("[Ghostpad] ===== Ghostpad v1.0 Starting =====\n");
    gp_log("[Ghostpad] Control port: %d\n", GP_PORT);

    /* ---- Initialize SCE User Service ---- */
    ret = sceUserServiceInitialize(NULL);
    gp_log("[Ghostpad] sceUserServiceInitialize: 0x%08x\n", ret);
    /* Negative here is OK — service may already be initialized by the system */

    /* Log both user service calls so we can compare them */
    int32_t fgUser = -1, initUser = -1;
    int fgRet   = sceUserServiceGetForegroundUser(&fgUser);
    int initRet = sceUserServiceGetInitialUser(&initUser);
    gp_log("[Ghostpad] GetForegroundUser: ret=0x%08x id=0x%08x\n",
           (uint32_t)fgRet, (uint32_t)fgUser);
    gp_log("[Ghostpad] GetInitialUser:    ret=0x%08x id=0x%08x\n",
           (uint32_t)initRet, (uint32_t)initUser);

    /* Prefer initial user — it's the primary logged-in user (typically 0x10000000).
     * GetForegroundUser in a system-service context may return a non-pad-accessible id. */
    if (initRet == 0 && initUser >= 0)
        userId = initUser;
    else if (fgRet == 0 && fgUser >= 0)
        userId = fgUser;
    else
        userId = 0x10000000;

    gp_log("[Ghostpad] using userId = 0x%08x\n", userId);
    notify("Ghostpad: userId 0x%08x", userId);

    /* ---- Phase 2: Validate userId ----
     *
     * GetForegroundUser from a system-service context returns session-context
     * IDs like 0x152fc488 that direct scePad IPC calls (scePadOpen, VirtualDevice)
     * do not accept.  Clamp to the canonical first-user value for those calls.
     *
     * IMPORTANT: keep the original (foreground) userId for the injected
     * SceShellCore/SceShellUI Mbus flow. Direct scePad calls still use the
     * clamped canonical value below. */
    int32_t injectUserId = userId;
    if ((uint32_t)userId < 0x10000000u || (uint32_t)userId > 0x1000000Fu) {
        gp_log("[Ghostpad] userId 0x%08x outside [0x10000000,0x1000000F], clamping for direct calls\n",
               (uint32_t)userId);
        userId = 0x10000000;
    } else {
        injectUserId = userId;  /* already canonical, both vars the same */
    }
    gp_log("[Ghostpad] directUserId=0x%08x  injectUserId=0x%08x\n",
           (uint32_t)userId, (uint32_t)injectUserId);

    /* ---- Elevate credentials ---- */
    elevate_credentials();

    /* Stay on GAME authid (0x3800000000010003) set by elevate_credentials().
     * The pad service IPC allow-list requires game authid for scePadGetHandle,
     * scePadVirtualDeviceInsertData, etc. Kernel-debugger authid breaks these.
     * mdbg_copyin is elevated locally in shellui_pad_relaunch_stub_with_handle. */
    gp_log("[Ghostpad] authid: game (pad service calls OK)\n");

    /* ---- Set Pad Process Privilege ---- */
    ret = scePadSetProcessPrivilege(1);
    gp_log("[Ghostpad] scePadSetProcessPrivilege(1): 0x%08x\n", ret);

    /* ---- Acquire pad handle ---- */

    /* scePadGetHandle — get existing handle without opening a new IPC connection */
    padHandle = scePadGetHandle(userId, 0, 0);
    gp_log("[Ghostpad] scePadGetHandle(type=0): 0x%08x\n", (uint32_t)padHandle);

    if (padHandle < 0) {
        /* Also try index 1 in case the user's pad is on slot 1 */
        padHandle = scePadGetHandle(userId, 0, 1);
        gp_log("[Ghostpad] scePadGetHandle(type=0,idx=1): 0x%08x\n", (uint32_t)padHandle);
    }

    /* scePadGetHandle type=3 — find an existing virtual DualSense from a prior run */
    if (padHandle < 0) {
        for (int _idx = 0; _idx < 4 && padHandle < 0; _idx++) {
            padHandle = scePadGetHandle(userId, 3, _idx);
            gp_log("[Ghostpad] scePadGetHandle(type=3,idx=%d): 0x%08x\n",
                   _idx, (uint32_t)padHandle);
        }
        if (padHandle >= 0) {
            gp_log("[Ghostpad] found existing virtual DualSense handle=%d\n", padHandle);
        }
    }

    if (padHandle >= 0) {
        gp_log("[Ghostpad] scePadGetHandle succeeded: handle=%d\n", padHandle);
    }

    /* scePadOpen — standard physical pad open */
    if (padHandle < 0) {
    padHandle = scePadOpen(userId, 0, 0, NULL);
    gp_log("[Ghostpad] scePadOpen(type=0): 0x%08x\n", (uint32_t)padHandle);

    if (padHandle >= 0) {
    }

    if (padHandle < 0) {
        /* scePadVirtualDeviceAddDevice — handle may be in struct fields, not return value */
        struct {
            int32_t size;    /* offset  0 — struct size */
            int32_t userId;  /* offset  4 — user ID     */
            int32_t pad[6];  /* offset  8..31            */
        } vd_param;

        /* Pre-clean orphaned virtual devices from a previous run */
        gp_log("[Ghostpad] VDA pre-clean: deleteDevice(0-511)\n");
        for (int dh = 0; dh < 512; dh++) {
            int32_t dr = scePadVirtualDeviceDeleteDevice(dh);
            if (dr == 0)
                gp_log("[Ghostpad] deleteDevice(%d): OK\n", dh);
            else if (dr != (int32_t)0x803b0003 && dr != (int32_t)0x803b0001)
                gp_log("[Ghostpad] deleteDevice(%d): 0x%08x\n", dh, (uint32_t)dr);
        }

        /* Sentinel pattern to detect which struct fields VDA writes to */
        const int32_t VDA_SENTINEL = (int32_t)0xDEADBEEF;
        memset(&vd_param, 0, sizeof(vd_param));
        vd_param.size   = (int32_t)sizeof(vd_param);
        vd_param.userId = userId;
        for (int k = 0; k < 6; k++) vd_param.pad[k] = VDA_SENTINEL;

        gp_log("[Ghostpad] VDA call: size=%d userId=0x%08x type=DualSense\n",
               vd_param.size, (uint32_t)vd_param.userId);

        ret = scePadVirtualDeviceAddDevice(&vd_param, VIRTUAL_DEVICE_TYPE_DUALSENSE);

        /* VDA writes handle to struct field, not return value — log all fields */
        gp_log("[Ghostpad] VDA ret=0x%08x  size=%d uid=0x%08x\n",
               (uint32_t)ret, vd_param.size, (uint32_t)vd_param.userId);
        gp_log("[Ghostpad] VDA pad[0-3]=0x%08x 0x%08x 0x%08x 0x%08x\n",
               (uint32_t)vd_param.pad[0], (uint32_t)vd_param.pad[1],
               (uint32_t)vd_param.pad[2], (uint32_t)vd_param.pad[3]);
        gp_log("[Ghostpad] VDA pad[4-5]=0x%08x 0x%08x\n",
               (uint32_t)vd_param.pad[4], (uint32_t)vd_param.pad[5]);

        if (ret >= 0) {
            padHandle = ret;
        } else {
            /* Check if VDA wrote the handle into a struct field despite the error */
            for (int k = 0; k < 6; k++) {
                if (vd_param.pad[k] != VDA_SENTINEL && vd_param.pad[k] >= 0) {
                    gp_log("[Ghostpad] VDA handle found in pad[%d] = %d\n",
                           k, vd_param.pad[k]);
                    padHandle = vd_param.pad[k];
                    break;
                }
            }
        }

        /* Retry VDA with SceShellCore authid (0x4800000000000010) */
        if (padHandle < 0) {
            pid_t mypid2 = getpid();
            uint64_t saved_authid2 = kernel_get_ucred_authid(mypid2);
            kernel_set_ucred_authid(mypid2, 0x4800000000000010l);

            memset(&vd_param, 0, sizeof(vd_param));
            vd_param.size   = (int32_t)sizeof(vd_param);
            vd_param.userId = userId;
            for (int k = 0; k < 6; k++) vd_param.pad[k] = VDA_SENTINEL;

            int32_t vda2 = scePadVirtualDeviceAddDevice(&vd_param, VIRTUAL_DEVICE_TYPE_DUALSENSE);
            gp_log("[Ghostpad] VDA(shellcore-authid) ret=0x%08x pad[0-3]=0x%08x 0x%08x 0x%08x 0x%08x\n",
                   (uint32_t)vda2,
                   (uint32_t)vd_param.pad[0], (uint32_t)vd_param.pad[1],
                   (uint32_t)vd_param.pad[2], (uint32_t)vd_param.pad[3]);

            kernel_set_ucred_authid(mypid2, saved_authid2);

            if (vda2 >= 0) {
                padHandle = vda2;
            } else {
                for (int k = 0; k < 6; k++) {
                    if (vd_param.pad[k] != VDA_SENTINEL && vd_param.pad[k] >= 0) {
                        gp_log("[Ghostpad] VDA(shellcore) handle in pad[%d]=%d\n",
                               k, vd_param.pad[k]);
                        padHandle = vd_param.pad[k];
                        break;
                    }
                }
            }
        }

        if (padHandle >= 0) {
            gp_log("[Ghostpad] VDA handle: %d\n", padHandle);

            /* Auto-press Cross to dismiss the "who is using this controller?" dialog */
            {
                ScePadData ap;
                memset(&ap, 0, sizeof(ap));
                ap.buttons           = SCE_PAD_BUTTON_CROSS;
                ap.leftStick.x       = 128;
                ap.leftStick.y       = 128;
                ap.rightStick.x      = 128;
                ap.rightStick.y      = 128;
                ap.connected         = 1;
                ap.quat.w            = 1.0f;

                sleep(1);  /* wait for PS5 UI dialog to render */
                ret = scePadVirtualDeviceInsertData(padHandle, &ap);
                gp_log("[Ghostpad] auto-press Cross: VDI ret=0x%08x\n", (uint32_t)ret);
                usleep(200000); /* 200ms hold */

                /* release */
                ap.buttons = 0;
                scePadVirtualDeviceInsertData(padHandle, &ap);
                usleep(100000);
            }
        } else {
            /* All direct pad methods failed; process injection attempted after listen() */
            gp_log("[Ghostpad] All direct pad methods failed; will try injection after listen()\n");
        }
    } /* end approach 3 if (padHandle < 0) */
    } /* end approach 1 outer if (padHandle < 0) */

    /* ---- Create TCP Server Socket ---- */
    serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        gp_log("[Ghostpad] socket() failed: errno=%d\n", errno);
        goto cleanup;
    }

    /* Allow port reuse so we can restart the payload without waiting.
     * SO_REUSEPORT is needed on FreeBSD when the previous payload's socket
     * is still in TIME_WAIT or a prior instance is partially alive. */
    int optval = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR,  &optval, sizeof(optval));
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEPORT,  &optval, sizeof(optval));
    setsockopt(serverFd, SOL_SOCKET, SO_NOSIGPIPE,  &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(GP_PORT);

    {
        int bind_ok = 0;
        for (int bi = 0; bi < 10; bi++) {
            if (bind(serverFd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                bind_ok = 1;
                break;
            }
            gp_log("[Ghostpad] bind() errno=%d, retry %d/10...\n", errno, bi + 1);
            sleep(2);
        }
        if (!bind_ok) {
            gp_log("[Ghostpad] bind() failed after retries; continuing diagnostic-only without GPAD server\n");
            close(serverFd);
            serverFd = -1;
        }
    }

    if (serverFd >= 0 && listen(serverFd, 1) < 0) {
        gp_log("[Ghostpad] listen() failed: errno=%d\n", errno);
        close(serverFd);
        serverFd = -1;
    }

    if (serverFd >= 0) {
        gp_log("[Ghostpad] Listening on 0.0.0.0:%d\n", GP_PORT);
        notify("Ghostpad: Listening on port %d", GP_PORT);
    }

    /* ---- Control server on port 6970 (non-blocking) for TYPE/GBND/HVDI/DISC ---- */
    {
        ctrlFd = socket(AF_INET, SOCK_STREAM, 0);
        if (ctrlFd >= 0) {
            int ov = 1;
            setsockopt(ctrlFd, SOL_SOCKET, SO_REUSEADDR, &ov, sizeof(ov));
            setsockopt(ctrlFd, SOL_SOCKET, SO_REUSEPORT, &ov, sizeof(ov));
            setsockopt(ctrlFd, SOL_SOCKET, SO_NOSIGPIPE, &ov, sizeof(ov));
            struct sockaddr_in ca;
            memset(&ca, 0, sizeof(ca));
            ca.sin_family = AF_INET;
            ca.sin_addr.s_addr = INADDR_ANY;
            ca.sin_port = htons(GP_CTRL_PORT);
            if (bind(ctrlFd, (struct sockaddr *)&ca, sizeof(ca)) == 0 &&
                listen(ctrlFd, 8) == 0) {
                /* Set non-blocking so we can poll during the injection wait loop */
                int flags = fcntl(ctrlFd, F_GETFL, 0);
                if (flags >= 0) fcntl(ctrlFd, F_SETFL, flags | O_NONBLOCK);
                gp_log("[Ghostpad] Control port %d ready (GBND)\n", GP_CTRL_PORT);
            } else {
                close(ctrlFd);
                ctrlFd = -1;
                gp_log("[Ghostpad] Control port bind failed errno=%d\n", errno);
            }
        }
    }

    /* ---- Process injection — attempted after listen() so server is already reachable ---- */
    if (padHandle < 0 && shellui_args == 0) {
        if (ctrlFd >= 0) {
            gp_log("[Ghostpad] Waiting briefly for TYPE config on port %d\n", GP_CTRL_PORT);
            for (int tw = 0; tw < 25; tw++) {
                int cfd = accept(ctrlFd, NULL, NULL);
                if (cfd >= 0) {
                    char magic[4];
                    set_recv_timeout_ms(cfd, 250);
                    int nr4 = recv_exact(cfd, magic, 4);
                    if (nr4 == 4 && memcmp(magic, "TYPE", 4) == 0) {
                        GhostpadTypePacket tpkt;
                        memcpy(tpkt.magic, magic, 4);
                        if (recv_exact(cfd, (char *)&tpkt + 4, GP_TYPE_PACKET_SIZE - 4) ==
                            (int)(GP_TYPE_PACKET_SIZE - 4)) {
                            virtual_device_type = (int32_t)tpkt.deviceType;
                            gp_log("[Ghostpad] TYPE: virtual_device_type=%d\n",
                                   virtual_device_type);
                        }
                    }
                    close(cfd);
                }
                usleep(200000);
            }
        }

        /* Patch libScePad VDA in SceShellCore to bypass assignment-screen return */
        gp_log("[Ghostpad] PATH 2: patching libScePad VDA in SceShellCore (dry run first)...\n");
        int pdry = shellui_pad_patch_vda(1);
        gp_log("[Ghostpad] patch_vda dry: matches=%d\n", pdry);
        if (pdry > 0) {
            gp_log("[Ghostpad] applying VDA patch...\n");
            int p = shellui_pad_patch_vda(0);
            gp_log("[Ghostpad] patch_vda applied: patches=%d\n", p);
            notify("Ghostpad: VDA patch applied %d", p);
        }

        gp_log("[Ghostpad] Attempting process injection...\n");
        gp_log("[Ghostpad] Injection mode: force_virtual_vda=1 type=%d\n",
               virtual_device_type);
        if (shellui_pad_inject(injectUserId, 1, virtual_device_type,
                               &shellui_pid, &shellui_args) == 0) {
            gp_log("[Ghostpad] Injection OK  pid=%d args=0x%lx\n",
                   shellui_pid, shellui_args);
            /* Wait 3s for SceShellCore stub to create the device */
            usleep(3000000);
            /* Poll for stub ready, and also poll ctrlFd for incoming GBND bind commands.
             * Python automation detects DEVICE_ADDED from klog and sends GBND here. */
            int32_t stub_ready = 0;
            int32_t stub_handle = -1;
            int32_t post_ready_polls = -1;
            gp_log("[Ghostpad] entering ctrlFd poll loop, ctrlFd=%d\n", ctrlFd);
            for (int w = 0; w < 325; w++) {  /* 325 × 200ms = 65s */
                /* Non-blocking check for GBND bind command */
                if (ctrlFd >= 0) {
                    int cfd = accept(ctrlFd, NULL, NULL);
                    if (cfd >= 0) {
                        gp_log("[Ghostpad] ctrlFd: accepted fd=%d at iter=%d\n", cfd, w);
                        set_recv_timeout_ms(cfd, 750);
                        /* Read 4-byte magic to decide packet type */
                        char magic[4];
                        int nr4 = recv_exact(cfd, magic, 4);
                        gp_log("[Ghostpad] ctrlFd: magic recv nr4=%d bytes='%c%c%c%c'\n",
                               nr4,
                               nr4>=1?magic[0]:'?', nr4>=2?magic[1]:'?',
                               nr4>=3?magic[2]:'?', nr4>=4?magic[3]:'?');
                        if (nr4 == 4 && memcmp(magic, "GBND", 4) == 0) {
                            GhostpadBindPacket bpkt;
                            memcpy(bpkt.magic, magic, 4);
                            int nr = recv_exact(cfd, (char *)&bpkt + 4, GP_BIND_PACKET_SIZE - 4);
                            close(cfd);
                            if (nr == (int)(GP_BIND_PACKET_SIZE - 4)) {
                                uint64_t vDevId   = bpkt.virtualDevId;
                                uint64_t pDevId   = bpkt.physicalDevId;
                                int32_t  bindUid  = (bpkt.userId != 0) ? (int32_t)bpkt.userId
                                                                        : injectUserId;
                                gp_log("[Ghostpad] GBND: virt=0x%llx phys=0x%llx user=0x%x\n",
                                       (unsigned long long)vDevId,
                                       (unsigned long long)pDevId, (uint32_t)bindUid);
                                bound_virtual_device_id = vDevId;

                                /* Step 1: evict physical device before binding virtual */
                                if (pDevId != 0) {
                                    int dr = shellui_pad_disconnect_device(pDevId);
                                    gp_log("[Ghostpad] disconnect_device ret=%d\n", dr);
                                    usleep(200000); /* 200ms for disconnect to propagate */
                                }

                                /* Step 2: bind virtual device to user */
                                int br = shellui_pad_force_bind(vDevId, bindUid);
                                gp_log("[Ghostpad] force_bind ret=%d\n", br);

                                if (br == 0) {
                                    int32_t dev_handle = (int32_t)(vDevId & 0xffffffffu);
                                    gp_log("[Ghostpad] force_bind succeeded; testing VDI (neutral) handle=0x%x\n",
                                           (uint32_t)dev_handle);
                                    /* Test VDI with neutral state — confirms VDI works without UI input */
                                    int dr = shellcore_pad_test_vdi_neutral(dev_handle);
                                    gp_log("[Ghostpad] GBND: deviceId vdi_neutral ret=%d\n", dr);
                                    if (dr == 0) {
                                        vdi_handle = dev_handle;
                                        device_vdi_ready = 1;
                                        if (shellui_pad_direct_adopt_vdi_handle(shellui_pid,
                                                shellui_args, dev_handle) == 0) {
                                            gp_log("[Ghostpad] GBND: adopted deviceId for direct SceShellCore VDI input\n");
                                        } else {
                                            gp_log("[Ghostpad] GBND: direct adopt of deviceId failed\n");
                                        }
                                        /* Re-launch stub with known handle for no-lag mdbg VDI path */
                                        if (padHandle < 0 && shellui_args != 0) {
                                            gp_log("[Ghostpad] GBND: relaunching stub for no-lag mdbg path...\n");
                                            int rl = shellui_pad_relaunch_stub_with_handle(dev_handle);
                                            gp_log("[Ghostpad] GBND: relaunch_stub ret=%d\n", rl);
                                            if (rl == 0) {
                                                /* Poll for stub ready=1 (up to 3s — shellui_stub+fp_vda=NULL: ~500ms) */
                                                for (int rw = 0; rw < 30; rw++) {
                                                    usleep(100000);
                                                    int32_t rdy = (int32_t)mdbg_getint(shellui_pid,
                                                        shellui_args + (intptr_t)offsetof(ShellUiPadArgs, ready));
                                                    if (rdy == 1) {
                                                        gp_log("[Ghostpad] GBND: stub ready! NO-LAG mdbg path active.\n");
                                                        notify("Ghostpad: mdbg VDI active");
                                                        device_vdi_ready = 2; /* sentinel: use mdbg path */
                                                        break;
                                                    }
                                                }
                                                if (device_vdi_ready != 2) {
                                                    gp_log("[Ghostpad] GBND: stub not ready after 3s; falling back to pt_call\n");
                                                }
                                            }
                                        }
                                    } else {
                                        gp_log("[Ghostpad] force_bind succeeded; waiting for HVDI fallback\n");
                                    }

                                    /* Direct VDI from our process using the raw deviceId */
                                    if (padHandle < 0) {
                                        ScePadData vdi_probe;
                                        memset(&vdi_probe, 0, sizeof(vdi_probe));
                                        vdi_probe.connected = 1;
                                        vdi_probe.quat.w   = 1.0f;
                                        vdi_probe.leftStick.x  = 128;
                                        vdi_probe.leftStick.y  = 128;
                                        vdi_probe.rightStick.x = 128;
                                        vdi_probe.rightStick.y = 128;
                                        int32_t dev_h = (int32_t)(vDevId & 0xffffffffu);
                                        int vr = scePadVirtualDeviceInsertData(dev_h, &vdi_probe);
                                        gp_log("[Ghostpad] direct-VDI from our process: devId=0x%x ret=0x%x\n",
                                               (uint32_t)dev_h, (uint32_t)vr);
                                        if (vr == 0) {
                                            padHandle = dev_h;
                                            gp_log("[Ghostpad] *** ZERO-LAG DIRECT VDI! padHandle=%d ***\n", padHandle);
                                            notify("Ghostpad: process injected VDI=%d", padHandle);
                                        }
                                    }

                                }
                            }
                        } else if (nr4 == 4 && memcmp(magic, "HVDI", 4) == 0) {
                            if (device_vdi_ready) {
                                gp_log("[Ghostpad] HVDI skipped; deviceId VDI already active\n");
                                close(cfd);
                                continue;
                            }
                            /* HVDI: CIM padHandle received — use for VDI input delivery */
                            GhostpadHvdiPacket hpkt;
                            memcpy(hpkt.magic, magic, 4);
                            int nr = recv_exact(cfd, (char *)&hpkt + 4, GP_HVDI_PACKET_SIZE - 4);
                            close(cfd);
                            if (nr == (int)(GP_HVDI_PACKET_SIZE - 4)) {
                                vdi_handle = (int32_t)hpkt.padHandle;
                                gp_log("[Ghostpad] HVDI: vdi_handle=0x%x\n",
                                       (uint32_t)vdi_handle);
                                /* Immediately test: send Cross via pt_call VDI with known handle */
                                if (vdi_handle > 0) {
                                    gp_log("[Ghostpad] HVDI: testing SceShellUI VDI Cross handle=0x%x...\n",
                                           (uint32_t)vdi_handle);
                                    int vr = shellui_pad_test_vdi_cross(vdi_handle);
                                    gp_log("[Ghostpad] HVDI: shellui vdi_cross ret=%d\n", vr);
                                    gp_log("[Ghostpad] HVDI: testing SceShellCore VDI Cross handle=0x%x...\n",
                                           (uint32_t)vdi_handle);
                                    int cr = shellcore_pad_test_vdi_cross(vdi_handle);
                                    gp_log("[Ghostpad] HVDI: shellcore vdi_cross ret=%d\n", cr);
                                    if (vr == 0 || cr == 0) {
                                    } else {
                                        if (bound_virtual_device_id != 0) {
                                            int32_t dev_handle = (int32_t)(bound_virtual_device_id & 0xffffffffu);
                                            gp_log("[Ghostpad] HVDI: testing virtual deviceId as VDI handle=0x%x...\n",
                                                   (uint32_t)dev_handle);
                                            int dr = shellcore_pad_test_vdi_cross(dev_handle);
                                            gp_log("[Ghostpad] HVDI: deviceId vdi_cross ret=%d\n", dr);
                                            if (dr == 0) {
                                                vdi_handle = dev_handle;
                                                device_vdi_ready = 1;
                                                if (shellui_pad_direct_adopt_vdi_handle(shellui_pid,
                                                        shellui_args, dev_handle) == 0) {
                                                    gp_log("[Ghostpad] HVDI: adopted deviceId for direct SceShellCore VDI input\n");
                                                } else {
                                                    gp_log("[Ghostpad] HVDI: direct adopt of deviceId failed\n");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (nr4 == 4 && memcmp(magic, "DISC", 4) == 0) {
                            int ddr = -1;
                            if (bound_virtual_device_id != 0) {
                                ddr = shellui_pad_disconnect_device(bound_virtual_device_id);
                            }
                            gp_log("[Ghostpad] DISC(ctrl): dev=0x%llx ret=%d\n",
                                   (unsigned long long)bound_virtual_device_id, ddr);
                            bound_virtual_device_id = 0;
                            vdi_handle = -1;
                            device_vdi_ready = 0;
                            close(cfd);
                        } else {
                            close(cfd);
                        }
                    }
                }
                stub_ready  = (int32_t)mdbg_getint(shellui_pid,
                    shellui_args + (intptr_t)offsetof(ShellUiPadArgs, ready));
                stub_handle = (int32_t)mdbg_getint(shellui_pid,
                    shellui_args + (intptr_t)offsetof(ShellUiPadArgs, pad_handle));
                if (stub_ready != 0) {
                    if (post_ready_polls < 0) {
                        post_ready_polls = 20; /* 4s grace to accept delayed HVDI */
                        gp_log("[Ghostpad] stub ready observed=%d handle=%d; keeping ctrlFd alive briefly\n",
                               stub_ready, stub_handle);
                    } else if (post_ready_polls-- <= 0) {
                        break;
                    }
                }
                usleep(200000);
            }
            gp_log("[Ghostpad] stub ready=%d pad_handle=%d injectUserId=0x%08x\n",
                   stub_ready, stub_handle, (uint32_t)injectUserId);
            if (stub_ready == 1) {
                notify("Ghostpad: inject OK handle=%d", stub_handle);
            } else if (shellui_pad_direct_usable(shellui_pid, shellui_args)) {
            } else {
                /* Log each probe's error code for diagnosis */
                for (int ri = 0; ri < 16; ri++) {
                    int32_t rce = (int32_t)mdbg_getint(shellui_pid,
                        shellui_args + (intptr_t)offsetof(ShellUiPadArgs, rc_log)
                        + (intptr_t)(ri * 4));
                    /* Print all slots unconditionally — 0 values are meaningful.
                     * rc_log[8..15] = vdp.f[0..7] from the first VDA call (uid=1). */
                    gp_log("[Ghostpad] stub rc_log[%d] = 0x%08x\n",
                           ri, (uint32_t)rce);
                }
                notify("Ghostpad: stub failed ready=%d", stub_ready);
            }
        } else {
            gp_log("[Ghostpad] Injection failed — running without pad input\n");
            notify("Ghostpad: no pad handle - check klog");
        }
    }

    if (serverFd < 0) {
        gp_log("[Ghostpad] Diagnostic-only run complete; GPAD server unavailable\n");
        goto cleanup;
    }

    /* ---- Main Accept Loop ---- */
    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        gp_log("[Ghostpad] Waiting for connection...\n");
        clientFd = accept(serverFd, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientFd < 0) {
            gp_log("[Ghostpad] accept() failed: errno=%d\n", errno);
            break;
        }

        {
            uint32_t ip = ntohl(clientAddr.sin_addr.s_addr);
            gp_log("[Ghostpad] Connected: %d.%d.%d.%d\n",
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                   (ip >> 8)  & 0xFF, ip & 0xFF);
            notify("Ghostpad: PC connected (%d.%d.%d.%d)",
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                   (ip >> 8)  & 0xFF, ip & 0xFF);
        }

        /* Disable Nagle for low-latency input */
#ifdef TCP_NODELAY
        setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
#endif

        /* ---- Packet Read Loop ---- */
        GhostpadPacket pkt;
        ScePadData     padData;
        uint64_t       pktCount = 0;
        int            directPadActive = 0;
        stats_reset(); /* reset server-side CPS counter for each new client */

        if (padHandle < 0 && shellui_args != 0 && device_vdi_ready == 2) {
            /* Stub relaunched with known handle — use shellui_pad_update (mdbg+PT_IO fallback). */
            gp_log("[Ghostpad] using NO-LAG mdbg_copyin path (device_vdi_ready=2)\n");
            directPadActive = 0;
        } else if (padHandle < 0 && shellui_args != 0 &&
            shellui_pad_direct_usable(shellui_pid, shellui_args)) {
            gp_log("[Ghostpad] direct VDI send path available (pt_call — may cause lag)\n");
            directPadActive = 1;
        } else if (padHandle < 0 && shellui_args != 0 &&
                   shellui_pad_direct_mode(shellui_pid, shellui_args) == 1) {
            gp_log("[Ghostpad] skipping unsafe direct remote-insert mode; using shared update path\n");
        }

        while (1) {
            int n = recv_exact(clientFd, &pkt, GP_PACKET_SIZE);
            if (n <= 0) {
                gp_log("[Ghostpad] Client disconnected (recv=%d, errno=%d, pkts=%llu)\n",
                            n, errno, (unsigned long long)pktCount);
                break;
            }

            /* Validate magic bytes */
            if (memcmp(pkt.magic, "DISC", 4) == 0) {
                int ddr = -1;
                if (bound_virtual_device_id != 0) {
                    ddr = shellui_pad_disconnect_device(bound_virtual_device_id);
                }
                gp_log("[Ghostpad] DISC(gpad): dev=0x%llx ret=%d\n",
                       (unsigned long long)bound_virtual_device_id, ddr);
                bound_virtual_device_id = 0;
                /* Keep device_vdi_ready/stub intact — stub still running, reuse on reconnect */
                break;
            }
            if (memcmp(pkt.magic, GP_MAGIC, GP_MAGIC_LEN) != 0) {
                gp_log("[Ghostpad] Bad magic: %02x %02x %02x %02x\n",
                            (uint8_t)pkt.magic[0], (uint8_t)pkt.magic[1],
                            (uint8_t)pkt.magic[2], (uint8_t)pkt.magic[3]);
                continue;
            }

            /* Build ScePadData from packet */
            memset(&padData, 0, sizeof(padData));
            padData.buttons                = ntohl(pkt.buttons);
            padData.leftStick.x            = pkt.lx;
            padData.leftStick.y            = pkt.ly;
            padData.rightStick.x           = pkt.rx;
            padData.rightStick.y           = pkt.ry;
            padData.analogButtons.l2       = pkt.l2;
            padData.analogButtons.r2       = pkt.r2;
            padData.connected              = 1;
            padData.quat.w                 = 1.0f; /* identity quaternion */

            /* Inject into pad — time the VDI call so we can measure its latency */
            {
                int is_press = (padData.buttons != 0);
                struct timeval vdi_t1, vdi_t2;
                uint64_t vdi_us = 0;

                gettimeofday(&vdi_t1, NULL);

                if (padHandle >= 0) {
                    ret = scePadVirtualDeviceInsertData(padHandle, &padData);
                    if (ret < 0 && pktCount == 0) {
                        gp_log("[Ghostpad] VDI InsertData failed: 0x%08x\n", ret);
                    }
                } else if (shellui_args != 0) {
                    ret = directPadActive
                        ? shellui_pad_direct_send(shellui_pid, shellui_args,
                                                  &padData, sizeof(padData))
                        : shellui_pad_update(shellui_pid, shellui_args,
                                             &padData, sizeof(padData));
                    if (ret < 0 && pktCount == 0) {
                        gp_log("[Ghostpad] shellui pad send failed pkt=0 ret=%d direct=%d\n",
                               ret, directPadActive);
                    }
                    if (pktCount == 4) {
                        int32_t r5 = (int32_t)mdbg_getint(shellui_pid,
                            shellui_args + (intptr_t)offsetof(ShellUiPadArgs, rc_log) + 20);
                        int32_t r6 = (int32_t)mdbg_getint(shellui_pid,
                            shellui_args + (intptr_t)offsetof(ShellUiPadArgs, rc_log) + 24);
                        gp_log("[Ghostpad] stub rc_log[5]=0x%08x (fp_insert) rc_log[6]=0x%08x (fp_vdi)\n",
                               (uint32_t)r5, (uint32_t)r6);
                    }
                }

                gettimeofday(&vdi_t2, NULL);
                vdi_us = (uint64_t)(vdi_t2.tv_sec  - vdi_t1.tv_sec)  * 1000000ULL +
                         (uint64_t)(vdi_t2.tv_usec - vdi_t1.tv_usec < 0
                             ? 0 : vdi_t2.tv_usec - vdi_t1.tv_usec);

                stats_record(is_press, ret, vdi_us);
            }

            pktCount++;
            /* Log throughput every 1000 packets */
            if (pktCount % 1000 == 0) {
                gp_log("[Ghostpad] speedup: %llu packets processed\n",
                       (unsigned long long)pktCount);
            }
        }

        close(clientFd);
        clientFd = -1;

        /* Zero out / center controller state after disconnect */
        memset(&padData, 0, sizeof(padData));
        padData.leftStick.x  = 128;
        padData.leftStick.y  = 128;
        padData.rightStick.x = 128;
        padData.rightStick.y = 128;
        padData.quat.w       = 1.0f;
        if (padHandle >= 0) {
            scePadVirtualDeviceInsertData(padHandle, &padData);
        } else if (shellui_args != 0) {
            if (directPadActive)
                shellui_pad_direct_send(shellui_pid, shellui_args,
                                        &padData, sizeof(padData));
            else
                shellui_pad_update(shellui_pid, shellui_args,
                                   &padData, sizeof(padData));
        }
        if (directPadActive) {
            shellui_pad_direct_end(shellui_pid, shellui_args);
        }

        notify("Ghostpad: PC disconnected. Listening again...");
    }

cleanup:
    gp_log("[Ghostpad] Cleaning up...\n");
    if (clientFd >= 0) close(clientFd);
    if (ctrlFd   >= 0) close(ctrlFd);
    if (serverFd >= 0) close(serverFd);
    if (padHandle >= 0) {
        scePadVirtualDeviceDeleteDevice(padHandle);
    }
    sceUserServiceTerminate();
    gp_log("[Ghostpad] Done.\n");
    return 0;
}
