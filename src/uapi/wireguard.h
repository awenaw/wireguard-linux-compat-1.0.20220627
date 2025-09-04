/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * 文档
 * ====
 *
 * 下列枚举与宏用于通过 Generic Netlink 与 WireGuard 交互，族名为
 * WG_GENL_NAME，版本为 WG_GENL_VERSION。定义了两种方法：get 与 set。
 * 它们共享许多属性，但接受的输入与输出略有不同。
 *
 * WG_CMD_GET_DEVICE
 * -----------------
 *
 * 仅可通过 NLM_F_REQUEST | NLM_F_DUMP 调用。命令体必须包含且仅包含以下二选一：
 *
 *    WGDEVICE_A_IFINDEX: NLA_U32
 *    WGDEVICE_A_IFNAME: NLA_NUL_STRING，最大长度 IFNAMSIZ - 1
 *
 * 内核将返回多条（NLM_F_MULTI）消息，包含如下嵌套属性树：
 *
 *    WGDEVICE_A_IFINDEX: NLA_U32
 *    WGDEVICE_A_IFNAME: NLA_NUL_STRING，最大长度 IFNAMSIZ - 1
 *    WGDEVICE_A_PRIVATE_KEY: NLA_EXACT_LEN，长度 WG_KEY_LEN
 *    WGDEVICE_A_PUBLIC_KEY: NLA_EXACT_LEN，长度 WG_KEY_LEN
 *    WGDEVICE_A_LISTEN_PORT: NLA_U16
 *    WGDEVICE_A_FWMARK: NLA_U32
 *    WGDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            WGPEER_A_PUBLIC_KEY: NLA_EXACT_LEN，长度 WG_KEY_LEN
 *            WGPEER_A_PRESHARED_KEY: NLA_EXACT_LEN，长度 WG_KEY_LEN
 *            WGPEER_A_ENDPOINT: NLA_MIN_LEN(struct sockaddr)，struct sockaddr_in 或 struct sockaddr_in6
 *            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16
 *            WGPEER_A_LAST_HANDSHAKE_TIME: NLA_EXACT_LEN，struct __kernel_timespec
 *            WGPEER_A_RX_BYTES: NLA_U64
 *            WGPEER_A_TX_BYTES: NLA_U64
 *            WGPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    WGALLOWEDIP_A_FAMILY: NLA_U16
 *                    WGALLOWEDIP_A_IPADDR: NLA_MIN_LEN(struct in_addr)，struct in_addr 或 struct in6_addr
 *                    WGALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            WGPEER_A_PROTOCOL_VERSION: NLA_U32
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * 单个 peer 的所有 allowed-ips 可能无法放入一条 Netlink 消息。此时，后续
 * 消息会继续写入同一 peer，但仅包含 WGPEER_A_PUBLIC_KEY 与 WGPEER_A_ALLOWEDIPS。
 * 同一 peer 可能连续出现多次，接收方需将相邻 peer 片段合并。同理，所有 peers
 * 也可能无法放入一条消息，后续消息只会包含 WGDEVICE_A_IFNAME 与 WGDEVICE_A_PEERS，
 * 仍需由接收方合并以形成完整 peers 列表。
 *
 * 由于该命令带有 NLA_F_DUMP，最后一条消息总是 NLMSG_DONE，即使发生错误。
 * NLMSG_DONE 内包含一个整数错误码：为 0 或负数 errno。
 *
 * WG_CMD_SET_DEVICE
 * -----------------
 *
 * 仅可通过 NLM_F_REQUEST 调用。命令体必须包含以下嵌套结构，且 IFINDEX 与 IFNAME 二选一：
 *
 *    WGDEVICE_A_IFINDEX: NLA_U32
 *    WGDEVICE_A_IFNAME: NLA_NUL_STRING，最大长度 IFNAMSIZ - 1
 *    WGDEVICE_A_FLAGS: NLA_U32，取 0 或 WGDEVICE_F_REPLACE_PEERS（先清空当前 peers 再添加下面的列表）
 *    WGDEVICE_A_PRIVATE_KEY: 长度 WG_KEY_LEN；置全零表示删除
 *    WGDEVICE_A_LISTEN_PORT: NLA_U16；为 0 表示随机选择
 *    WGDEVICE_A_FWMARK: NLA_U32；为 0 表示禁用
 *    WGDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            WGPEER_A_PUBLIC_KEY: 长度 WG_KEY_LEN
 *            WGPEER_A_FLAGS: NLA_U32，取 0 以及/或以下标志：
 *                            WGPEER_F_REMOVE_ME（该 peer 最终不应存在，而非新增/更新）和/或
 *                            WGPEER_F_REPLACE_ALLOWEDIPS（在添加列表前清空该 peer 的 allowed-ips）和/或
 *                            WGPEER_F_UPDATE_ONLY（仅在 peer 已存在时才设置）。
 *            WGPEER_A_PRESHARED_KEY: 长度 WG_KEY_LEN；置全零表示删除
 *            WGPEER_A_ENDPOINT: struct sockaddr_in 或 struct sockaddr_in6
 *            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16；为 0 表示禁用
 *            WGPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    WGALLOWEDIP_A_FAMILY: NLA_U16
 *                    WGALLOWEDIP_A_IPADDR: struct in_addr 或 struct in6_addr
 *                    WGALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            WGPEER_A_PROTOCOL_VERSION: NLA_U32，大多数用户不应设置/使用；当未设置时采用最新协议；
 *                                       否则必须设置为 1。
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * 当配置数据超过内核可接受的最大消息长度时，应连续发送多条消息，每条补充前一条未包含的信息。
 * 若首条消息设置了 WGDEVICE_F_REPLACE_PEERS，通常后续片段不应再次设置，以避免多次清空，
 * 使得第一次清空后，后续仅追加。对 peer 同理：若首条 peer 片段设置了 WGPEER_F_REPLACE_ALLOWEDIPS，
 * 后续该 peer 的片段不应再次设置该标志。
 *
 * 发生错误时，将以 NLMSG_ERROR 回复，并包含 errno。
 */

/*
 * 高层概览
 * ========
 *
 * 本 UAPI 头文件定义了用于在用户态配置/查看 WireGuard 设备的 Generic Netlink ABI。
 * 消息采用如下通用嵌套结构（Generic Netlink + Netlink TLV）：
 *
 *   nlmsghdr
 *     └─ genlmsghdr (family: "wireguard", version: 1)
 *          └─ attributes (struct nlattr TLVs)
 *             ├─ WGDEVICE_*（设备级属性）
 *             │    └─ WGDEVICE_A_PEERS (NLA_NESTED)
 *             │         ├─ [peer #0] (NLA_NESTED)
 *             │         │    ├─ WGPEER_*（节点属性）
 *             │         │    └─ WGPEER_A_ALLOWEDIPS (NLA_NESTED)
 *             │         │         ├─ [allowedip #0] (NLA_NESTED)
 *             │         │         │    └─ WGALLOWEDIP_*（允许 IP 属性）
 *             │         │         └─ [allowedip #1] (NLA_NESTED)
 *             │         └─ [peer #1] (NLA_NESTED)
 *             └─ ...（其他设备级属性）
 *
 * 关键尺寸
 * --------
 * - WG_KEY_LEN 为 32 字节（公钥/私钥/预共享密钥）。
 * - 端点为 IPv4 的 struct sockaddr_in 或 IPv6 的 struct sockaddr_in6。
 * - “上次握手” 时间使用 struct __kernel_timespec。
 *
 * GET 与 SET 的消息形态
 * ----------------------
 * - WG_CMD_GET_DEVICE（dump）：
 *   输入：IFINDEX 与 IFNAME 二选一；
 *   输出：一条或多条 NLM_F_MULTI 消息，表示完整设备状态；内核可能将 peers/allowed-ips
 *   分片到多条消息中，接收端需按 IFNAME/IFINDEX 与 peer 公钥合并相邻片段。
 *
 * - WG_CMD_SET_DEVICE（request）：
 *   输入：IFINDEX 与 IFNAME 二选一，加上待修改属性。
 *   注意：
 *     • PRIVATE_KEY 全零表示删除私钥；
 *     • LISTEN_PORT 为 0 表示随机端口；
 *     • FWMARK 为 0 表示禁用；
 *     • WGDEVICE_F_REPLACE_PEERS 在应用提供的列表前清空所有 peers（若分片，仅首片设置）；
 *     • 对每个 peer，WGPEER_F_REPLACE_ALLOWEDIPS 先清空后添加（若分片，仅该 peer 的首片设置）；
 *     • WGPEER_F_UPDATE_ONLY 仅在 peer 已存在时更新，不会新建；
 *     • WGPEER_A_PRESHARED_KEY 全零表示删除预共享密钥；
 *     • WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL 为 0 表示禁用 keepalive。
 *
 * 分片与合并
 * ----------
 * - 大配置可能超过单条 Netlink 消息的上限，无论 GET 的回复还是 SET 的请求都可能分片。
 * - 对 GET：
 *     • 同一 peer 可在连续多条消息中出现，仅携带 PUBLIC_KEY + ALLOWEDIPS 以续传列表；
 *     • 后续设备片段可能只包含 IFNAME + PEERS；
 * - 对 SET：
 *     • 连续发送多条消息；后续片段不再重复 REPLACE_* 标志；
 *     • 对同一 peer 的后续片段不再重复 REPLACE_ALLOWEDIPS；
 * - 接收端按（设备, peer 公钥）合并相邻片段。
 *
 * 错误语义
 * --------
 * - GET（dump）：以 NLMSG_DONE 结束；错误码（若有）位于 NLMSG_DONE 载荷（0 或 -errno）。
 * - SET（request）：出错时以 NLMSG_ERROR 回复，携带 -errno。
 *
 * 最小示例（示意）
 * --------------
 * GET（dump）：
 *   请求：{ WGDEVICE_A_IFNAME = "wg0" }
 *   回复片段：
 *     #1 { IFINDEX, IFNAME, PRIVATE_KEY, PUBLIC_KEY, LISTEN_PORT, FWMARK,
 *          PEERS = [ { PUBLIC_KEY, PRESHARED_KEY, ENDPOINT, ...,
 *                      ALLOWEDIPS = [ { FAMILY, IPADDR, CIDR_MASK }, ... ] },
 *                    { PUBLIC_KEY, ... } ] }
 *     #2 { IFNAME, PEERS = [ { PUBLIC_KEY（同上）, ALLOWEDIPS = [ ...续... ] } ] }
 *     ...
 *     #N NLMSG_DONE { error = 0 }
 *
 * SET（request）：
 *   消息 #1 {
 *     IFNAME = "wg0",
 *     FLAGS = WGDEVICE_F_REPLACE_PEERS,
 *     LISTEN_PORT = 51820,
 *     PEERS = [
 *       { PUBLIC_KEY = <32B>, FLAGS = WGPEER_F_REPLACE_ALLOWEDIPS,
 *         ENDPOINT = <sockaddr>, PERSISTENT_KEEPALIVE_INTERVAL = 25,
 *         ALLOWEDIPS = [ { FAMILY=AF_INET, IPADDR=10.0.0.2, CIDR_MASK=32 },
 *                         { FAMILY=AF_INET6, IPADDR=fd00::2, CIDR_MASK=128 } ] },
 *       { PUBLIC_KEY = <32B>, FLAGS = 0, ... }
 *     ]
 *   }
 *   消息 #2 {
 *     IFNAME = "wg0",
 *     PEERS = [ { PUBLIC_KEY = <same>, ALLOWEDIPS = [ ...more... ] } ]
 *   }
 */

/*
 * 中文总览
 * ========
 *
 * 本头文件定义了 WireGuard 的 Generic Netlink UAPI（族名 "wireguard"，版本 1），
 * 供用户态程序配置与查询设备。消息采用 TLV 嵌套：设备属性包含 peers，peer 又包含
 * allowed-ips。关键字段：密钥 32 字节；端点为 IPv4/IPv6 sockaddr；握手时间为
 * __kernel_timespec。GET 为 dump，多条消息返回并可能分片；SET 为 request，可分片
 * 连续发送。分片合并按 (设备, peer 公钥) 进行。错误：GET 以 NLMSG_DONE 携带错误码；
 * SET 以 NLMSG_ERROR 返回 errno。
 */

#ifndef _WG_UAPI_WIREGUARD_H
#define _WG_UAPI_WIREGUARD_H

#define WG_GENL_NAME "wireguard" /* Generic Netlink 家族名 */
#define WG_GENL_VERSION 1         /* UAPI 版本号 */

#define WG_KEY_LEN 32             /* 密钥长度（字节）：公钥/私钥/预共享密钥 */

/*
 * Commands
 * --------
 * - WG_CMD_GET_DEVICE: Dump the state of a single device (by IFINDEX/IFNAME).
 * - WG_CMD_SET_DEVICE: Create/update device and peer configuration.
 */
/*
 * 命令（Generic Netlink）
 * ----------------------
 * - WG_CMD_GET_DEVICE：按 IFINDEX/IFNAME 查询单个设备当前状态（dump）。
 * - WG_CMD_SET_DEVICE：创建/更新设备与节点配置（request）。
 */
enum wg_cmd {
	WG_CMD_GET_DEVICE, /* 查询设备状态（dump） */
	WG_CMD_SET_DEVICE, /* 设置设备/节点配置（request） */
	__WG_CMD_MAX
};
#define WG_CMD_MAX (__WG_CMD_MAX - 1)

/*
 * Device Flags (WGDEVICE_A_FLAGS)
 * -------------------------------
 * - WGDEVICE_F_REPLACE_PEERS: Before applying provided WGDEVICE_A_PEERS, clear
 *   all existing peers on the target device. For fragmented SET, include this
 *   only in the first fragment to avoid repeated clearing.
 */
/*
 * 设备标志（WGDEVICE_A_FLAGS）
 * ---------------------------
 * - WGDEVICE_F_REPLACE_PEERS：在应用 WGDEVICE_A_PEERS 之前清空现有 peers；
 *   若 SET 分片，仅在第一片设置，避免重复清空。
 */
enum wgdevice_flag {
	WGDEVICE_F_REPLACE_PEERS = 1U << 0, /* 在应用提供的 peers 前先清空现有 peers */
	__WGDEVICE_F_ALL = WGDEVICE_F_REPLACE_PEERS
};

/*
 * Device Attributes (top-level)
 * -----------------------------
 * - WGDEVICE_A_IFINDEX (u32): Kernel ifindex (mutually exclusive with IFNAME).
 * - WGDEVICE_A_IFNAME (string): Interface name (mutually exclusive with IFINDEX).
 * - WGDEVICE_A_PRIVATE_KEY (32B): All zeros to remove private key.
 * - WGDEVICE_A_PUBLIC_KEY (32B): Derived; read-only in practice (GET output).
 * - WGDEVICE_A_FLAGS (u32): See wgdevice_flag.
 * - WGDEVICE_A_LISTEN_PORT (u16): 0 to choose randomly.
 * - WGDEVICE_A_FWMARK (u32): 0 to disable fwmark.
 * - WGDEVICE_A_PEERS (nested): Sequence of peer entries (wgpeer_attribute).
 */
/*
 * 设备属性（顶层）
 * --------------
 * - WGDEVICE_A_IFINDEX：接口 ifindex（与 IFNAME 互斥）。
 * - WGDEVICE_A_IFNAME：接口名（与 IFINDEX 互斥）。
 * - WGDEVICE_A_PRIVATE_KEY：32 字节，全零表示删除私钥。
 * - WGDEVICE_A_PUBLIC_KEY：32 字节，派生得到；通常只读（GET 输出）。
 * - WGDEVICE_A_FLAGS：设备标志，见 wgdevice_flag。
 * - WGDEVICE_A_LISTEN_PORT：监听端口，0 表示随机选择。
 * - WGDEVICE_A_FWMARK：fwmark，0 表示禁用。
 * - WGDEVICE_A_PEERS：节点列表（嵌套），元素由 wgpeer_attribute 描述。
 */
enum wgdevice_attribute {
	WGDEVICE_A_UNSPEC,        /* 未指定/占位 */
	WGDEVICE_A_IFINDEX,       /* u32: 接口 ifindex（与 IFNAME 互斥） */
	WGDEVICE_A_IFNAME,        /* NUL 结尾字符串: 接口名（与 IFINDEX 互斥） */
	WGDEVICE_A_PRIVATE_KEY,   /* 32B: 私钥；全零表示删除 */
	WGDEVICE_A_PUBLIC_KEY,    /* 32B: 公钥；查询输出只读 */
	WGDEVICE_A_FLAGS,         /* u32: 设备标志，见 wgdevice_flag */
	WGDEVICE_A_LISTEN_PORT,   /* u16: 监听端口；0 表示随机 */
	WGDEVICE_A_FWMARK,        /* u32: fwmark；0 表示禁用 */
	WGDEVICE_A_PEERS,         /* 嵌套: 节点数组（见 wgpeer_attribute） */
	__WGDEVICE_A_LAST
};
#define WGDEVICE_A_MAX (__WGDEVICE_A_LAST - 1)

/*
 * Peer Flags (WGPEER_A_FLAGS)
 * ---------------------------
 * - WGPEER_F_REMOVE_ME: Remove this peer (takes precedence over other fields).
 * - WGPEER_F_REPLACE_ALLOWEDIPS: Clear current allowed-ips, then add provided.
 * - WGPEER_F_UPDATE_ONLY: Do not create new peer; only update if it exists.
 */
/*
 * 节点标志（WGPEER_A_FLAGS）
 * -------------------------
 * - WGPEER_F_REMOVE_ME：移除此节点（优先于其他字段）。
 * - WGPEER_F_REPLACE_ALLOWEDIPS：清空现有 allowed-ips，再添加提供的列表。
 * - WGPEER_F_UPDATE_ONLY：仅更新已存在节点，不会新建。
 */
enum wgpeer_flag {
	WGPEER_F_REMOVE_ME = 1U << 0,        /* 移除此节点（优先级最高） */
	WGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,/* 清空并替换 allowed-ips */
	WGPEER_F_UPDATE_ONLY = 1U << 2,       /* 仅更新已存在节点，不新建 */
	__WGPEER_F_ALL = WGPEER_F_REMOVE_ME | WGPEER_F_REPLACE_ALLOWEDIPS |
			 WGPEER_F_UPDATE_ONLY
};

/*
 * Peer Attributes (nested under WGDEVICE_A_PEERS)
 * -----------------------------------------------
 * - WGPEER_A_PUBLIC_KEY (32B): Peer identity; used to merge fragments.
 * - WGPEER_A_PRESHARED_KEY (32B): All zeros to remove preshared key.
 * - WGPEER_A_FLAGS (u32): See wgpeer_flag.
 * - WGPEER_A_ENDPOINT (sockaddr_in/sockaddr_in6): Remote UDP endpoint.
 * - WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL (u16 seconds): 0 disables.
 * - WGPEER_A_LAST_HANDSHAKE_TIME (__kernel_timespec): GET-only informational.
 * - WGPEER_A_RX_BYTES (u64): Received bytes counter (GET-only).
 * - WGPEER_A_TX_BYTES (u64): Transmitted bytes counter (GET-only).
 * - WGPEER_A_ALLOWEDIPS (nested): Sequence of allowed IP entries.
 * - WGPEER_A_PROTOCOL_VERSION (u32): Normally omitted; set to 1 only if needed.
 */
/*
 * 节点属性（嵌套在 WGDEVICE_A_PEERS 下）
 * -----------------------------------
 * - WGPEER_A_PUBLIC_KEY：32 字节，节点身份；用于分片合并。
 * - WGPEER_A_PRESHARED_KEY：32 字节，全零表示删除预共享密钥。
 * - WGPEER_A_FLAGS：节点标志，见 wgpeer_flag。
 * - WGPEER_A_ENDPOINT：远端 UDP 端点（IPv4/IPv6）。
 * - WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL：保活间隔（秒），0 表示禁用。
 * - WGPEER_A_LAST_HANDSHAKE_TIME：上次握手时间（仅 GET）。
 * - WGPEER_A_RX_BYTES：接收字节数（仅 GET）。
 * - WGPEER_A_TX_BYTES：发送字节数（仅 GET）。
 * - WGPEER_A_ALLOWEDIPS：允许的 IP 列表（嵌套）。
 * - WGPEER_A_PROTOCOL_VERSION：通常省略；必要时设为 1。
 */
enum wgpeer_attribute {
	WGPEER_A_UNSPEC,                       /* 未指定/占位 */
	WGPEER_A_PUBLIC_KEY,                   /* 32B: 节点公钥（分片合并依据） */
	WGPEER_A_PRESHARED_KEY,                /* 32B: 预共享密钥；全零表示删除 */
	WGPEER_A_FLAGS,                        /* u32: 节点标志，见 wgpeer_flag */
	WGPEER_A_ENDPOINT,                     /* sockaddr_in/sockaddr_in6: 远端端点 */
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,/* u16: 保活秒数；0 禁用 */
	WGPEER_A_LAST_HANDSHAKE_TIME,          /* __kernel_timespec: 上次握手（仅 GET） */
	WGPEER_A_RX_BYTES,                     /* u64: 接收字节数（仅 GET） */
	WGPEER_A_TX_BYTES,                     /* u64: 发送字节数（仅 GET） */
	WGPEER_A_ALLOWEDIPS,                   /* 嵌套: 允许的 IP 列表 */
	WGPEER_A_PROTOCOL_VERSION,             /* u32: 协议版本；常省略，必要时=1 */
	__WGPEER_A_LAST
};
#define WGPEER_A_MAX (__WGPEER_A_LAST - 1)

/*
 * AllowedIP Attributes (nested under WGPEER_A_ALLOWEDIPS)
 * -------------------------------------------------------
 * - WGALLOWEDIP_A_FAMILY (u16): AF_INET or AF_INET6.
 * - WGALLOWEDIP_A_IPADDR: struct in_addr (IPv4) or struct in6_addr (IPv6).
 * - WGALLOWEDIP_A_CIDR_MASK (u8): CIDR prefix length, 0..32 (IPv4) or 0..128 (IPv6).
 */
/*
 * AllowedIP 属性（嵌套在 WGPEER_A_ALLOWEDIPS 下）
 * ---------------------------------------------
 * - WGALLOWEDIP_A_FAMILY：地址族（AF_INET 或 AF_INET6）。
 * - WGALLOWEDIP_A_IPADDR：IPv4 用 struct in_addr；IPv6 用 struct in6_addr。
 * - WGALLOWEDIP_A_CIDR_MASK：前缀长度，IPv4 为 0..32；IPv6 为 0..128。
 */
enum wgallowedip_attribute {
	WGALLOWEDIP_A_UNSPEC,   /* 未指定/占位 */
	WGALLOWEDIP_A_FAMILY,   /* u16: AF_INET / AF_INET6 */
	WGALLOWEDIP_A_IPADDR,   /* struct in_addr / struct in6_addr */
	WGALLOWEDIP_A_CIDR_MASK,/* u8: 前缀长度（IPv4:0..32 / IPv6:0..128） */
	__WGALLOWEDIP_A_LAST
};
#define WGALLOWEDIP_A_MAX (__WGALLOWEDIP_A_LAST - 1)

#endif /* _WG_UAPI_WIREGUARD_H */
