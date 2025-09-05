/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * 版权所有 (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. 保留所有权利.
 *
 * ===============================================================================
 * WireGuard 用户空间 API (UAPI) 接口定义
 * ===============================================================================
 *
 * 本头文件定义了用户态程序与 WireGuard 内核模块通信的 Generic Netlink 接口。
 * 通过此接口可以配置和查询 WireGuard 设备的状态，包括：
 * • 设备参数（私钥、监听端口、fwmark 等）
 * • 对等节点（peer）管理
 * • 允许的 IP 地址路由配置
 * • 统计信息查询
 *
 * 通信架构图：
 * ┌─────────────────┐    Generic Netlink    ┌─────────────────┐
 * │   用户态程序    │ ◄─────────────────────► │ WireGuard 内核  │
 * │  (wg, wg-quick) │   family:"wireguard"   │     模块        │
 * │                 │   version: 1           │                 │
 * └─────────────────┘                        └─────────────────┘
 *
 * 族名: WG_GENL_NAME = "wireguard"
 * 版本: WG_GENL_VERSION = 1
 *
 * 支持两种主要命令：
 * 1. WG_CMD_GET_DEVICE - 查询设备状态（dump 操作）
 * 2. WG_CMD_SET_DEVICE - 配置设备和对等节点（request 操作）
 *
 * ===============================================================================
 * WG_CMD_GET_DEVICE 命令详解
 * ===============================================================================
 *
 * 【用途】查询指定 WireGuard 设备的完整状态信息
 * 【调用方式】NLM_F_REQUEST | NLM_F_DUMP
 *
 * ┌─ 请求消息结构 ─┐
 * │ nlmsghdr       │
 * │  ├─ type: 族ID │
 * │  ├─ flags: NLM_F_REQUEST | NLM_F_DUMP
 * │  └─ ...        │
 * │ genlmsghdr     │
 * │  ├─ cmd: WG_CMD_GET_DEVICE
 * │  └─ version: 1 │
 * │ 属性 (二选一):  │
 * │  ├─ WGDEVICE_A_IFINDEX: 接口索引 (u32)
 * │  └─ WGDEVICE_A_IFNAME: 接口名 (字符串, 最长 IFNAMSIZ-1)
 * └───────────────┘
 *
 * ┌─ 响应消息结构 ─┐ (可能多条消息，带 NLM_F_MULTI 标志)
 * │ 消息 #1:       │
 * │  WGDEVICE_A_IFINDEX: 接口索引
 * │  WGDEVICE_A_IFNAME: 接口名称
 * │  WGDEVICE_A_PRIVATE_KEY: 私钥 (32字节)
 * │  WGDEVICE_A_PUBLIC_KEY: 公钥 (32字节)
 * │  WGDEVICE_A_LISTEN_PORT: 监听端口
 * │  WGDEVICE_A_FWMARK: 防火墙标记
 * │  WGDEVICE_A_PEERS: [嵌套数组]
 * │    ├─ 对等节点 #0:
 * │    │    WGPEER_A_PUBLIC_KEY: 节点公钥 (32字节)
 * │    │    WGPEER_A_PRESHARED_KEY: 预共享密钥 (32字节)
 * │    │    WGPEER_A_ENDPOINT: 端点地址 (sockaddr_in/sockaddr_in6)
 * │    │    WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: 保活间隔 (秒)
 * │    │    WGPEER_A_LAST_HANDSHAKE_TIME: 最后握手时间
 * │    │    WGPEER_A_RX_BYTES: 接收字节数
 * │    │    WGPEER_A_TX_BYTES: 发送字节数
 * │    │    WGPEER_A_ALLOWEDIPS: [嵌套数组]
 * │    │      ├─ 允许IP #0:
 * │    │      │    WGALLOWEDIP_A_FAMILY: 地址族 (AF_INET/AF_INET6)
 * │    │      │    WGALLOWEDIP_A_IPADDR: IP地址 (in_addr/in6_addr)
 * │    │      │    WGALLOWEDIP_A_CIDR_MASK: 子网掩码长度 (0-32/128)
 * │    │      └─ 允许IP #1: ...
 * │    │    WGPEER_A_PROTOCOL_VERSION: 协议版本
 * │    └─ 对等节点 #1: ...
 * │ 消息 #2: (大数据分片时)
 * │  WGDEVICE_A_IFNAME: 接口名称
 * │  WGDEVICE_A_PEERS:
 * │    └─ 节点续传 (仅包含 PUBLIC_KEY + ALLOWEDIPS)
 * │ ...
 * │ NLMSG_DONE: 结束标记 (包含错误码: 0=成功, <0=errno)
 * └───────────────┘
 *
 * 【重要】分片处理机制：
 * • 当单个对等节点的允许IP列表过长时，会分布在多条消息中
 * • 后续分片仅包含 WGPEER_A_PUBLIC_KEY + WGPEER_A_ALLOWEDIPS
 * • 接收端需根据公钥合并同一节点的数据
 * • 所有对等节点也可能跨消息分片，后续消息仅含 IFNAME + PEERS
 *
 * ===============================================================================
 * WG_CMD_SET_DEVICE 命令详解
 * ===============================================================================
 *
 * 【用途】创建或更新 WireGuard 设备及其对等节点配置
 * 【调用方式】NLM_F_REQUEST
 *
 * ┌─ 请求消息结构 ─┐
 * │ nlmsghdr       │
 * │  ├─ type: 族ID │
 * │  ├─ flags: NLM_F_REQUEST
 * │  └─ ...        │
 * │ genlmsghdr     │
 * │  ├─ cmd: WG_CMD_SET_DEVICE
 * │  └─ version: 1 │
 * │ 必选 (二选一):  │
 * │  ├─ WGDEVICE_A_IFINDEX: 接口索引 (u32)
 * │  └─ WGDEVICE_A_IFNAME: 接口名 (字符串)
 * │ 可选设备属性:   │
 * │  ├─ WGDEVICE_A_FLAGS: 设备标志位
 * │  │    └─ WGDEVICE_F_REPLACE_PEERS: 替换前先清空所有节点
 * │  ├─ WGDEVICE_A_PRIVATE_KEY: 私钥 (32字节，全零=删除)
 * │  ├─ WGDEVICE_A_LISTEN_PORT: 监听端口 (0=随机)
 * │  ├─ WGDEVICE_A_FWMARK: 防火墙标记 (0=禁用)
 * │  └─ WGDEVICE_A_PEERS: [对等节点数组]
 * │       ├─ 节点 #0: [嵌套结构]
 * │       │    ├─ WGPEER_A_PUBLIC_KEY: 节点公钥 (32字节，必选)
 * │       │    ├─ WGPEER_A_FLAGS: 节点标志位
 * │       │    │    ├─ WGPEER_F_REMOVE_ME: 删除此节点
 * │       │    │    ├─ WGPEER_F_REPLACE_ALLOWEDIPS: 替换允许IP列表
 * │       │    │    └─ WGPEER_F_UPDATE_ONLY: 仅更新已存在节点
 * │       │    ├─ WGPEER_A_PRESHARED_KEY: 预共享密钥 (全零=删除)
 * │       │    ├─ WGPEER_A_ENDPOINT: 端点地址 (sockaddr)
 * │       │    ├─ WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: 保活间隔
 * │       │    ├─ WGPEER_A_ALLOWEDIPS: [允许IP数组]
 * │       │    │    ├─ IP #0:
 * │       │    │    │    ├─ WGALLOWEDIP_A_FAMILY: AF_INET/AF_INET6
 * │       │    │    │    ├─ WGALLOWEDIP_A_IPADDR: IP地址
 * │       │    │    │    └─ WGALLOWEDIP_A_CIDR_MASK: 前缀长度
 * │       │    │    └─ IP #1: ...
 * │       │    └─ WGPEER_A_PROTOCOL_VERSION: 协议版本 (通常省略)
 * │       └─ 节点 #1: ...
 * └───────────────┘
 *
 * ┌─ 响应消息 ─┐
 * │ 成功: ACK  │ (空载荷)
 * │ 失败: NLMSG_ERROR + errno
 * └───────────┘
 *
 * 【重要】配置语义：
 * • 私钥全零: 删除设备私钥 (将断开所有连接)
 * • 监听端口为0: 内核随机选择可用端口
 * • fwmark为0: 禁用防火墙标记
 * • 预共享密钥全零: 删除对等节点的PSK
 * • 保活间隔为0: 禁用该节点的持久保活
 *
 * 【重要】分片发送机制：
 * • 大配置可能需要多条消息发送
 * • WGDEVICE_F_REPLACE_PEERS 仅在首条消息中设置
 * • WGPEER_F_REPLACE_ALLOWEDIPS 仅在该节点的首个分片中设置
 * • 后续分片为增量添加，避免重复清空
 *
 * ===============================================================================
 * 数据流向图
 * ===============================================================================
 *
 *  用户态工具 (wg)                    内核态模块 (wireguard.ko)
 * ┌─────────────────┐                 ┌──────────────────────────┐
 * │                 │ GET_DEVICE      │                          │
 * │  wg show wg0    │ ──────────────► │  查询设备状态            │
 * │                 │ ◄────────────── │  返回完整配置+统计       │
 * │                 │                 │                          │
 * │  wg set wg0     │ SET_DEVICE      │                          │
 * │    private-key  │ ──────────────► │  更新设备配置            │
 * │    peer ABC...  │ ◄────────────── │  返回操作结果            │
 * │                 │                 │                          │
 * └─────────────────┘                 └──────────────────────────┘
 *        │                                       │
 *        └─ 通过 Generic Netlink Socket ─────────┘
 *           Family: "wireguard", Version: 1
 *
 * ===============================================================================
 * 关键数据结构说明
 * ===============================================================================
 *
 * WG_KEY_LEN = 32 字节
 * ├─ 用于所有密钥: 私钥、公钥、预共享密钥
 * └─ 基于 Curve25519 椭圆曲线密码学
 *
 * 端点地址:
 * ├─ IPv4: struct sockaddr_in (16字节)
 * └─ IPv6: struct sockaddr_in6 (28字节)
 *
 * 时间戳: struct __kernel_timespec
 * ├─ tv_sec: 秒数 (64位)
 * └─ tv_nsec: 纳秒数 (64位)
 *
 * 流量统计: u64 (最大 18EB)
 * ├─ RX_BYTES: 累计接收字节数
 * └─ TX_BYTES: 累计发送字节数
 *
 * ===============================================================================
 * 错误处理机制
 * ===============================================================================
 *
 * GET_DEVICE (dump):
 * ├─ 成功: 一系列 NLM_F_MULTI 消息 + NLMSG_DONE(errno=0)
 * └─ 失败: 部分数据 + NLMSG_DONE(errno<0)
 *
 * SET_DEVICE (request):
 * ├─ 成功: ACK 消息
 * └─ 失败: NLMSG_ERROR + errno
 *     ├─ -ENODEV: 设备不存在
 *     ├─ -EINVAL: 参数无效
 *     ├─ -EPERM: 权限不足
 *     └─ -ENOMEM: 内存不足
 *
 * ===============================================================================
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

#ifndef _WG_UAPI_WIREGUARD_H
#define _WG_UAPI_WIREGUARD_H

/*
 * ===============================================================================
 * 基本常量定义
 * ===============================================================================
 */

#define WG_GENL_NAME "wireguard"  /* Generic Netlink 家族名称 */
#define WG_GENL_VERSION 1         /* UAPI 版本号 */

#define WG_KEY_LEN 32             /* 密钥长度（字节）- 适用于所有密钥类型：
                                   * • 设备私钥/公钥 (Curve25519)
                                   * • 对等节点公钥 (Curve25519) 
                                   * • 预共享密钥 (PSK)
                                   * 全部基于 32 字节的加密强度 */

/*
 * ===============================================================================
 * Generic Netlink 命令定义
 * ===============================================================================
 */

/**
 * enum wg_cmd - WireGuard Generic Netlink 命令类型
 * 
 * 这些命令通过 Generic Netlink 套接字发送，用于与 WireGuard 内核模块通信。
 * 每个命令都有特定的调用模式和预期的属性集合。
 */
enum wg_cmd {
	/**
	 * WG_CMD_GET_DEVICE - 查询设备状态
	 * 
	 * 【操作类型】NLM_F_REQUEST | NLM_F_DUMP
	 * 【输入要求】WGDEVICE_A_IFINDEX 或 WGDEVICE_A_IFNAME 之一
	 * 【输出格式】多条 NLM_F_MULTI 消息 + NLMSG_DONE
	 * 【用途说明】获取指定 WireGuard 接口的完整配置和统计信息，
	 *           包括设备密钥、监听端口、所有对等节点及其状态
	 */
	WG_CMD_GET_DEVICE,
	
	/**
	 * WG_CMD_SET_DEVICE - 配置设备和对等节点
	 * 
	 * 【操作类型】NLM_F_REQUEST
	 * 【输入要求】WGDEVICE_A_IFINDEX 或 WGDEVICE_A_IFNAME 之一，
	 *           加上需要修改的属性
	 * 【输出格式】ACK（成功）或 NLMSG_ERROR（失败）
	 * 【用途说明】创建新的 WireGuard 接口或修改现有接口的配置，
	 *           支持原子性的多节点批量操作
	 */
	WG_CMD_SET_DEVICE,
	
	__WG_CMD_MAX         /* 内部使用：命令数量上限 */
};
#define WG_CMD_MAX (__WG_CMD_MAX - 1)

/*
 * ===============================================================================
 * 设备标志位定义 (WGDEVICE_A_FLAGS)
 * ===============================================================================
 */

/**
 * enum wgdevice_flag - 设备操作标志位
 * 
 * 这些标志位用于 WG_CMD_SET_DEVICE 命令中的 WGDEVICE_A_FLAGS 属性，
 * 控制设备配置的具体行为。可以组合使用（按位或操作）。
 */
enum wgdevice_flag {
	/**
	 * WGDEVICE_F_REPLACE_PEERS - 替换模式标志
	 * 
	 * 【作用】在应用新的对等节点列表之前，先清除设备上的所有现有节点
	 * 【使用场景】完全重新配置设备的节点列表，而非增量添加
	 * 【分片注意】当配置数据需要分片发送时：
	 *   • 仅在第一个消息片段中设置此标志
	 *   • 后续片段不应重复设置，避免多次清空操作
	 *   • 这确保了只在开始时清空一次，然后逐步添加所有节点
	 * 
	 * 示例：如果设备当前有节点 A、B，而配置包含节点 C、D，
	 *      则最终结果为仅有节点 C、D（A、B 被删除）
	 */
	WGDEVICE_F_REPLACE_PEERS = 1U << 0,
	
	__WGDEVICE_F_ALL = WGDEVICE_F_REPLACE_PEERS  /* 所有有效标志位的掩码 */
};

/*
 * ===============================================================================
 * 设备属性定义 (顶层 TLV 属性)
 * ===============================================================================
 */

/**
 * enum wgdevice_attribute - WireGuard 设备级别属性
 * 
 * 这些属性用于 Generic Netlink 消息的顶层 TLV 结构中，描述整个 WireGuard 设备
 * 的配置参数。每个属性都有特定的数据类型和语义。
 */
enum wgdevice_attribute {
	/**
	 * WGDEVICE_A_UNSPEC - 未指定属性
	 * 
	 * 【类型】无效值
	 * 【用途】占位符，不应在实际消息中使用
	 */
	WGDEVICE_A_UNSPEC,
	
	/**
	 * WGDEVICE_A_IFINDEX - 网络接口索引
	 * 
	 * 【类型】u32 (NLA_U32)
	 * 【用途】通过内核分配的接口索引标识设备
	 * 【约束】与 WGDEVICE_A_IFNAME 互斥，必须二选一
	 * 【应用】适用于已知接口索引的程序化操作
	 */
	WGDEVICE_A_IFINDEX,
	
	/**
	 * WGDEVICE_A_IFNAME - 网络接口名称
	 * 
	 * 【类型】NUL 结尾字符串 (NLA_NUL_STRING)
	 * 【长度】最大 IFNAMSIZ-1 字节（通常为 15 字节）
	 * 【用途】通过接口名称标识设备（如 "wg0", "wg-server"）
	 * 【约束】与 WGDEVICE_A_IFINDEX 互斥，必须二选一
	 * 【应用】适用于用户友好的命令行工具
	 */
	WGDEVICE_A_IFNAME,
	
	/**
	 * WGDEVICE_A_PRIVATE_KEY - 设备私钥
	 * 
	 * 【类型】32 字节二进制数据 (NLA_EXACT_LEN, WG_KEY_LEN)
	 * 【加密】Curve25519 私钥
	 * 【SET 语义】设置设备的私钥；全零缓冲区表示删除当前私钥
	 * 【GET 语义】返回当前设备私钥（敏感信息）
	 * 【安全性】删除私钥将断开所有现有连接并阻止新连接
	 */
	WGDEVICE_A_PRIVATE_KEY,
	
	/**
	 * WGDEVICE_A_PUBLIC_KEY - 设备公钥
	 * 
	 * 【类型】32 字节二进制数据 (NLA_EXACT_LEN, WG_KEY_LEN)
	 * 【加密】Curve25519 公钥
	 * 【SET 语义】通常不使用，由私钥自动派生
	 * 【GET 语义】返回当前设备公钥（从私钥派生）
	 * 【用途】其他对等节点需要此公钥来建立连接
	 */
	WGDEVICE_A_PUBLIC_KEY,
	
	/**
	 * WGDEVICE_A_FLAGS - 设备操作标志
	 * 
	 * 【类型】u32 (NLA_U32)
	 * 【取值】wgdevice_flag 枚举值的按位组合
	 * 【用途】控制 SET 操作的具体行为
	 * 【常用】WGDEVICE_F_REPLACE_PEERS 用于完全替换节点列表
	 */
	WGDEVICE_A_FLAGS,
	
	/**
	 * WGDEVICE_A_LISTEN_PORT - UDP 监听端口
	 * 
	 * 【类型】u16 (NLA_U16)
	 * 【范围】1-65535，0 表示内核随机选择
	 * 【用途】WireGuard 协议的 UDP 端口号
	 * 【默认】0（自动分配）
	 * 【注意】更改端口可能导致连接暂时中断
	 */
	WGDEVICE_A_LISTEN_PORT,
	
	/**
	 * WGDEVICE_A_FWMARK - 防火墙标记
	 * 
	 * 【类型】u32 (NLA_U32)
	 * 【用途】为 WireGuard 发出的数据包设置 SO_MARK
	 * 【取值】0 表示禁用，非零表示具体的标记值
	 * 【应用】配合 iptables/netfilter 规则实现策略路由
	 * 【用例】避免路由循环，实现流量分流等
	 */
	WGDEVICE_A_FWMARK,
	
	/**
	 * WGDEVICE_A_PEERS - 对等节点列表
	 * 
	 * 【类型】嵌套属性数组 (NLA_NESTED)
	 * 【结构】包含多个 wgpeer_attribute 类型的嵌套元素
	 * 【索引】每个数组元素以连续的数字索引（0, 1, 2...）为 nla_type
	 * 【分片】大列表可能跨越多条 Netlink 消息
	 * 【合并】接收端需按节点公钥合并来自不同消息的片段
	 */
	WGDEVICE_A_PEERS,
	
	__WGDEVICE_A_LAST        /* 内部使用：属性数量上限 */
};
#define WGDEVICE_A_MAX (__WGDEVICE_A_LAST - 1)

/*
 * ===============================================================================
 * 对等节点标志位定义 (WGPEER_A_FLAGS)
 * ===============================================================================
 */

/**
 * enum wgpeer_flag - 对等节点操作标志位
 * 
 * 这些标志位用于 WG_CMD_SET_DEVICE 命令中的 WGPEER_A_FLAGS 属性，
 * 控制单个对等节点配置的具体行为。可以组合使用。
 */
enum wgpeer_flag {
	/**
	 * WGPEER_F_REMOVE_ME - 删除节点标志
	 * 
	 * 【作用】删除指定的对等节点
	 * 【优先级】最高优先级，覆盖其他所有操作
	 * 【行为】如果设置此标志，会忽略同一消息中的其他属性
	 * 【用途】从设备上完全移除与该节点的所有关联
	 * 【结果】节点及其所有 allowed-ips 都会被清理
	 */
	WGPEER_F_REMOVE_ME = 1U << 0,
	
	/**
	 * WGPEER_F_REPLACE_ALLOWEDIPS - 替换 allowed-ips 标志
	 * 
	 * 【作用】在添加新的 allowed-ips 之前，先清除该节点的所有现有规则
	 * 【行为】对该节点执行原子性的“清空+添加”操作
	 * 【对比】不设置时为增量添加，设置时为完全替换
	 * 【分片注意】对同一节点，仅在第一个片段中设置
	 * 【使用场景】重新定义节点的路由规则，而非增量修改
	 */
	WGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,
	
	/**
	 * WGPEER_F_UPDATE_ONLY - 仅更新模式标志
	 * 
	 * 【作用】仅对已存在的节点进行更新，不会创建新节点
	 * 【防护】避免意外创建不需要的节点
	 * 【失败行为】如果节点不存在，操作将失败返回错误
	 * 【应用】适用于谨慎的配置更新场景
	 * 【组合】可与其他标志组合使用（除 REMOVE_ME 外）
	 */
	WGPEER_F_UPDATE_ONLY = 1U << 2,
	
	__WGPEER_F_ALL = WGPEER_F_REMOVE_ME | WGPEER_F_REPLACE_ALLOWEDIPS |
			 WGPEER_F_UPDATE_ONLY  /* 所有有效标志位的掩码 */
};

/*
 * ===============================================================================
 * 对等节点属性定义 (嵌套在 WGDEVICE_A_PEERS 下)
 * ===============================================================================
 */

/**
 * enum wgpeer_attribute - 对等节点属性定义
 * 
 * 这些属性定义了单个对等节点的完整配置和状态信息。
 * 每个节点都嵌套在 WGDEVICE_A_PEERS 数组中作为一个 TLV 元素。
 */
enum wgpeer_attribute {
	/**
	 * WGPEER_A_UNSPEC - 未指定属性
	 * 
	 * 【类型】无效值
	 * 【用途】占位符，不应在实际消息中使用
	 */
	WGPEER_A_UNSPEC,
	
	/**
	 * WGPEER_A_PUBLIC_KEY - 节点公钥（必选）
	 * 
	 * 【类型】32 字节二进制数据 (NLA_EXACT_LEN, WG_KEY_LEN)
	 * 【加密】Curve25519 公钥
	 * 【作用】节点的唯一标识符，用于所有操作和识别
	 * 【必选性】所有节点相关操作都必须包含此属性
	 * 【分片】在多条消息的分片中用作合并依据
	 * 【来源】由对端的私钥派生生成
	 */
	WGPEER_A_PUBLIC_KEY,
	
	/**
	 * WGPEER_A_PRESHARED_KEY - 预共享密钥 (PSK)
	 * 
	 * 【类型】32 字节二进制数据 (NLA_EXACT_LEN, WG_KEY_LEN)
	 * 【加密】随机生成的对称密钥
	 * 【用途】提供额外的加密层，增强量子计算机抗性
	 * 【可选性】可以省略，但建议高安全环境中使用
	 * 【SET 语义】全零缓冲区表示删除现有 PSK
	 * 【GET 语义】返回当前 PSK（敏感信息）
	 */
	WGPEER_A_PRESHARED_KEY,
	
	/**
	 * WGPEER_A_FLAGS - 节点操作标志
	 * 
	 * 【类型】u32 (NLA_U32)
	 * 【取值】wgpeer_flag 枚举值的按位组合
	 * 【用途】控制该节点的 SET 操作行为
	 * 【常用标志】REMOVE_ME, REPLACE_ALLOWEDIPS, UPDATE_ONLY
	 */
	WGPEER_A_FLAGS,
	
	/**
	 * WGPEER_A_ENDPOINT - 远端网络端点
	 * 
	 * 【类型】struct sockaddr_in (IPv4) 或 struct sockaddr_in6 (IPv6)
	 * 【用途】指定对端的 UDP 地址和端口
	 * 【动态性】可以在运行时更新（端点漫游）
	 * 【NAT 支持】WireGuard 会自动学习对端的实际 IP:Port
	 * 【可选性】可以省略，但会影响主动连接能力
	 * 【防火墙】确保对应端口在防火墙中允许 UDP 通信
	 */
	WGPEER_A_ENDPOINT,
	
	/**
	 * WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL - 持续保活间隔
	 * 
	 * 【类型】u16 秒数 (NLA_U16)
	 * 【范围】0-65535，0 表示禁用保活
	 * 【用途】定期发送 keepalive 数据包保持连接活跃
	 * 【NAT 穿越】帮助维持 NAT/防火墙的端口映射
	 * 【能耗平衡】过短增加网络负载，过长可能导致断连
	 * 【推荐值】25 秒是常用的平衡值
	 */
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	
	/**
	 * WGPEER_A_LAST_HANDSHAKE_TIME - 最后一次成功握手时间
	 * 
	 * 【类型】struct __kernel_timespec (NLA_EXACT_LEN)
	 * 【可用性】仅在 GET 操作中返回，SET 操作中忽略
	 * 【精度】纳秒级精度，但通常只关心秒级精度
	 * 【用途】判断连接状态、诊断网络问题
	 * 【初始值】全零表示从未成功握手
	 * 【更新机制】仅在成功完成 Noise 握手后更新
	 */
	WGPEER_A_LAST_HANDSHAKE_TIME,
	
	/**
	 * WGPEER_A_RX_BYTES - 累计接收字节数
	 * 
	 * 【类型】u64 (NLA_U64)
	 * 【可用性】仅在 GET 操作中返回
	 * 【统计内容】与该节点通信的所有接收数据量
	 * 【计数粒度】包括 WireGuard 协议头部在内的所有字节
	 * 【持久性】重启后清零，不跨越重启保存
	 * 【溢出】理论上可达 18EB，实际中没有溢出风险
	 */
	WGPEER_A_RX_BYTES,
	
	/**
	 * WGPEER_A_TX_BYTES - 累计发送字节数
	 * 
	 * 【类型】u64 (NLA_U64)
	 * 【可用性】仅在 GET 操作中返回
	 * 【统计内容】发送给该节点的所有数据量
	 * 【计数粒度】包括 WireGuard 协议头部在内的所有字节
	 * 【持久性】重启后清零，不跨越重启保存
	 * 【用途】流量监控、账单统计、网络诊断
	 */
	WGPEER_A_TX_BYTES,
	
	/**
	 * WGPEER_A_ALLOWEDIPS - 允许的 IP 地址范围列表
	 * 
	 * 【类型】嵌套属性数组 (NLA_NESTED)
	 * 【结构】包含多个 wgallowedip_attribute 类型的嵌套元素
	 * 【索引】每个数组元素以连续数字索引为 nla_type
	 * 【用途】定义哪些源 IP 可以通过该节点路由
	 * 【路由表】内核根据此列表构建内部路由決策树
	 * 【分片】大列表可能跨越多条 Netlink 消息
	 * 【重叠】不同节点的允许范围可以重叠，最具体的匹配优先
	 */
	WGPEER_A_ALLOWEDIPS,
	
	/**
	 * WGPEER_A_PROTOCOL_VERSION - 协议版本号
	 * 
	 * 【类型】u32 (NLA_U32)
	 * 【默认值】省略时使用最新版本
	 * 【当前版本】1（唯一支持的版本）
	 * 【使用建议】大多数情况下不应设置此值
	 * 【兼容性】未来版本升级时可能用于强制指定
	 * 【实现细节】仅在特殊兼容性需求时才设置为 1
	 */
	WGPEER_A_PROTOCOL_VERSION,
	
	__WGPEER_A_LAST          /* 内部使用：属性数量上限 */
};
#define WGPEER_A_MAX (__WGPEER_A_LAST - 1)

/*
 * ===============================================================================
 * 允许 IP 地址属性定义 (嵌套在 WGPEER_A_ALLOWEDIPS 下)
 * ===============================================================================
 */

/**
 * enum wgallowedip_attribute - 允许 IP 地址范围属性
 * 
 * 这些属性定义了单个 IP 地址范围条目，用于指定哪些源 IP 地址
 * 可以通过对应的对等节点进行路由。每个 IP 范围条目都包含地址族、
 * 网络地址和子网掩码三个组成部分。
 */
enum wgallowedip_attribute {
	/**
	 * WGALLOWEDIP_A_UNSPEC - 未指定属性
	 * 
	 * 【类型】无效值
	 * 【用途】占位符，不应在实际消息中使用
	 */
	WGALLOWEDIP_A_UNSPEC,
	
	/**
	 * WGALLOWEDIP_A_FAMILY - 地址族标识
	 * 
	 * 【类型】u16 (NLA_U16)
	 * 【取值】AF_INET (2) 或 AF_INET6 (10)
	 * 【用途】指定后续 IP 地址和掩码的解释方式
	 * 【必选性】每个 IP 范围条目都必须包含此属性
	 * 【数据一致性】必须与 WGALLOWEDIP_A_IPADDR 的实际数据类型一致
	 */
	WGALLOWEDIP_A_FAMILY,
	
	/**
	 * WGALLOWEDIP_A_IPADDR - 网络地址
	 * 
	 * 【IPv4 类型】struct in_addr (4 字节)
	 * 【IPv6 类型】struct in6_addr (16 字节)
	 * 【数据格式】网络字节序 (big-endian)
	 * 【用途】指定允许访问范围的网络地址部分
	 * 【配合使用】与 WGALLOWEDIP_A_CIDR_MASK 组合形成 CIDR 表示法
	 * 【示例】
	 *   IPv4: 192.168.1.0 + /24 表示 192.168.1.0-192.168.1.255
	 *   IPv6: 2001:db8:: + /64 表示 2001:db8::/64 子网
	 */
	WGALLOWEDIP_A_IPADDR,
	
	/**
	 * WGALLOWEDIP_A_CIDR_MASK - 子网掩码前缀长度
	 * 
	 * 【类型】u8 (NLA_U8)
	 * 【IPv4 范围】0-32（对应 32 位地址）
	 * 【IPv6 范围】0-128（对应 128 位地址）
	 * 【语义】指定地址的前多少位用于网络标识
	 * 【特殊值】
	 *   0: 匹配所有地址 (0.0.0.0/0 或 ::/0)
	 *   32/128: 仅匹配单一主机地址
	 * 【路由优先级】前缀越长（值越大）优先级越高
	 */
	WGALLOWEDIP_A_CIDR_MASK,
	
	__WGALLOWEDIP_A_LAST     /* 内部使用：属性数量上限 */
};
#define WGALLOWEDIP_A_MAX (__WGALLOWEDIP_A_LAST - 1)

/*
 * ===============================================================================
 * 文件结束标记
 * ===============================================================================
 * 
 * 本 UAPI 头文件定义了 WireGuard 的完整 Generic Netlink 接口。
 * 主要包含以下组成部分：
 * 
 * 1. 基本常量：WG_GENL_NAME, WG_GENL_VERSION, WG_KEY_LEN
 * 2. 命令类型：WG_CMD_GET_DEVICE, WG_CMD_SET_DEVICE
 * 3. 设备标志：WGDEVICE_F_REPLACE_PEERS
 * 4. 设备属性：9 个设备级别配置参数
 * 5. 节点标志：WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS, WGPEER_F_UPDATE_ONLY
 * 6. 节点属性：11 个节点级别配置参数
 * 7. 允许IP属性：4 个 IP 范围配置参数
 * 
 * 通过这些接口定义，用户态程序可以完整地管理 WireGuard 设备的
 * 所有配置参数和查询运行状态。
 */

#endif /* _WG_UAPI_WIREGUARD_H */
