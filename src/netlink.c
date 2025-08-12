// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * WireGuard Netlink 接口实现
 *
 * 本文件实现了 WireGuard 的 netlink 接口，为用户空间提供
 * 设备配置和状态信息访问功能。它使用通用 netlink 协议来
 * 暴露 WireGuard 特定的操作。
 *
 * netlink 接口支持两个主要操作：
 * 1. WG_CMD_GET_DEVICE - 检索设备配置和对等体状态
 * 2. WG_CMD_SET_DEVICE - 配置设备设置和管理对等体
 *
 * 主要组件：
 * - 用于验证用户输入的 Netlink 属性策略
 * - 设备查找和接口验证
 * - 对等体配置和管理
 * - 允许 IP 路由表管理
 * - 加密密钥的安全处理
 *
 * 实现遵循 netlink 协议进行正确的消息处理，
 * 包括对大型对等体列表的多部分转储支持。
 */

#include "netlink.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"
#include "uapi/wireguard.h"
#include <linux/if.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <crypto/algapi.h>

/* WireGuard 操作的通用 netlink 族 */
static struct genl_family genl_family;

/*
 * Netlink 属性验证策略
 * 这些定义了从用户空间传递的 netlink 消息中每个属性的
 * 预期数据类型和约束条件。
 */

/* 设备属性策略 - 验证设备配置的属性 */
static const struct nla_policy device_policy[WGDEVICE_A_MAX + 1] = {
	[WGDEVICE_A_IFINDEX]		= { .type = NLA_U32 },                          /* 网络接口索引 */
	[WGDEVICE_A_IFNAME]		= { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 }, /* 网络接口名称 */
	[WGDEVICE_A_PRIVATE_KEY]	= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),    /* 设备私钥（32字节）*/
	[WGDEVICE_A_PUBLIC_KEY]		= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),    /* 设备公钥（32字节）*/
	[WGDEVICE_A_FLAGS]		= { .type = NLA_U32 },                          /* 配置标志 */
	[WGDEVICE_A_LISTEN_PORT]	= { .type = NLA_U16 },                          /* UDP 监听端口 */
	[WGDEVICE_A_FWMARK]		= { .type = NLA_U32 },                          /* SO_MARK 防火墙标记 */
	[WGDEVICE_A_PEERS]		= { .type = NLA_NESTED }                        /* 嵌套的对等体属性 */
};

/* 对等体属性策略 - 验证对等体配置的属性 */
static const struct nla_policy peer_policy[WGPEER_A_MAX + 1] = {
	[WGPEER_A_PUBLIC_KEY]				= NLA_POLICY_EXACT_LEN(NOISE_PUBLIC_KEY_LEN),      /* 对等体公钥（32字节）*/
	[WGPEER_A_PRESHARED_KEY]			= NLA_POLICY_EXACT_LEN(NOISE_SYMMETRIC_KEY_LEN),   /* 预共享密钥（32字节）*/
	[WGPEER_A_FLAGS]				= { .type = NLA_U32 },                            /* 对等体配置标志 */
	[WGPEER_A_ENDPOINT]				= NLA_POLICY_MIN_LEN(sizeof(struct sockaddr)),    /* 对等体端点（IP + 端口）*/
	[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]	= { .type = NLA_U16 },                            /* 保活间隔（秒）*/
	[WGPEER_A_LAST_HANDSHAKE_TIME]			= NLA_POLICY_EXACT_LEN(sizeof(struct __kernel_timespec)), /* 最后握手时间戳 */
	[WGPEER_A_RX_BYTES]				= { .type = NLA_U64 },                            /* 从对等体接收的字节数 */
	[WGPEER_A_TX_BYTES]				= { .type = NLA_U64 },                            /* 发送到对等体的字节数 */
	[WGPEER_A_ALLOWEDIPS]				= { .type = NLA_NESTED },                         /* 嵌套的允许 IP */
	[WGPEER_A_PROTOCOL_VERSION]			= { .type = NLA_U32 }                             /* WireGuard 协议版本 */
};

/* 允许 IP 属性策略 - 验证对等体的 IP 路由条目 */
static const struct nla_policy allowedip_policy[WGALLOWEDIP_A_MAX + 1] = {
	[WGALLOWEDIP_A_FAMILY]		= { .type = NLA_U16 },                          /* 地址族（AF_INET/AF_INET6）*/
	[WGALLOWEDIP_A_IPADDR]		= NLA_POLICY_MIN_LEN(sizeof(struct in_addr)),   /* IP 地址（IPv4/IPv6）*/
	[WGALLOWEDIP_A_CIDR_MASK]	= { .type = NLA_U8 }                           /* CIDR 前缀长度（0-32/128）*/
};

/*
 * lookup_interface - 查找并验证 WireGuard 网络接口
 * @attrs: 包含接口标识符的 Netlink 属性
 * @skb: 包含请求的 netlink 套接字缓冲区
 *
 * 此函数通过索引或名称查找网络接口，并验证它是一个 WireGuard 接口。
 * 它确保提供了恰好一个标识符（索引或名称，不能同时提供或都不提供）。
 *
 * 返回值：指向 wg_device 结构的指针，失败时返回错误指针
 * 错误码：
 *  -EBADR: 同时提供或都未提供接口标识符
 *  -ENODEV: 未找到接口
 *  -EOPNOTSUPP: 接口不是 WireGuard 设备
 */
static struct wg_device *lookup_interface(struct nlattr **attrs,
					  struct sk_buff *skb)
{
	struct net_device *dev = NULL;

	/* 确保提供了恰好一个接口标识符 */
	if (!attrs[WGDEVICE_A_IFINDEX] == !attrs[WGDEVICE_A_IFNAME])
		return ERR_PTR(-EBADR);

	/* 在套接字的网络命名空间中通过索引或名称查找接口 */
	if (attrs[WGDEVICE_A_IFINDEX])
		dev = dev_get_by_index(sock_net(skb->sk),
				       nla_get_u32(attrs[WGDEVICE_A_IFINDEX]));
	else if (attrs[WGDEVICE_A_IFNAME])
		dev = dev_get_by_name(sock_net(skb->sk),
				      nla_data(attrs[WGDEVICE_A_IFNAME]));

	if (!dev)
		return ERR_PTR(-ENODEV);

	/* 验证这确实是一个 WireGuard 接口 */
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);  /* 返回错误前释放引用 */
		return ERR_PTR(-EOPNOTSUPP);
	}

	/* 从网络设备私有数据返回 WireGuard 设备结构 */
	return netdev_priv(dev);
}

/*
 * get_allowedips - 为允许的 IP 条目构造 netlink 消息
 * @skb: 写入 netlink 消息的套接字缓冲区
 * @ip: IP 地址字节（IPv4 或 IPv6）
 * @cidr: CIDR 前缀长度
 * @family: 地址族（AF_INET 或 AF_INET6）
 *
 * 此函数构造一个嵌套的 netlink 属性，包含对等体的单个允许
 * IP 地址/子网的信息。嵌套结构包括地址族、IP 地址和 CIDR 掩码。
 *
 * 返回值：成功时返回 0，缓冲区空间不足时返回 -EMSGSIZE
 */
static int get_allowedips(struct sk_buff *skb, const u8 *ip, u8 cidr,
			  int family)
{
	struct nlattr *allowedip_nest;

	/* 为此允许 IP 条目开始一个嵌套属性 */
	allowedip_nest = nla_nest_start(skb, 0);
	if (!allowedip_nest)
		return -EMSGSIZE;

	/* 向嵌套属性添加 CIDR 掩码、地址族和 IP 地址 */
	if (nla_put_u8(skb, WGALLOWEDIP_A_CIDR_MASK, cidr) ||
	    nla_put_u16(skb, WGALLOWEDIP_A_FAMILY, family) ||
	    nla_put(skb, WGALLOWEDIP_A_IPADDR, family == AF_INET6 ?
		    sizeof(struct in6_addr) : sizeof(struct in_addr), ip)) {
		/* 如果任何属性添加失败，取消嵌套结构 */
		nla_nest_cancel(skb, allowedip_nest);
		return -EMSGSIZE;
	}

	/* 完成嵌套属性 */
	nla_nest_end(skb, allowedip_nest);
	return 0;
}

/*
 * dump_ctx - netlink 转储操作的上下文结构
 * @wg: 正在转储的 WireGuard 设备
 * @next_peer: 在多部分转储中要处理的下一个对等体
 * @allowedips_seq: 用于允许 IP 一致性检查的序列号
 * @next_allowedip: 要处理的下一个允许 IP 条目
 *
 * 此结构在 netlink 转储操作期间维护状态，当数据太多无法放入
 * 单个消息时，转储可以跨越多个 netlink 消息。内核使用此结构
 * 从上一条消息中断的地方恢复转储。
 */
struct dump_ctx {
	struct wg_device *wg;                    /* 正在转储的设备 */
	struct wg_peer *next_peer;               /* 要转储的下一个对等体 */
	u64 allowedips_seq;                      /* 用于一致性的序列号 */
	struct allowedips_node *next_allowedip;  /* 要转储的下一个允许 IP */
};

/* 从 netlink 回调访问转储上下文的辅助宏 */
#define DUMP_CTX(cb) ((struct dump_ctx *)(cb)->args)

/*
 * get_peer - Construct netlink message for a peer's information
 * @peer: The WireGuard peer to dump
 * @skb: Socket buffer to write the netlink message to
 * @ctx: Dump context for handling multi-part dumps
 *
 * This function builds a netlink message containing all information about
 * a single peer, including its public key, endpoint, statistics, and allowed
 * IP addresses. It handles partial dumps when the message becomes too large.
 *
 * Returns: 0 on success, -EMSGSIZE if buffer space is insufficient
 */
static int
get_peer(struct wg_peer *peer, struct sk_buff *skb, struct dump_ctx *ctx)
{
	struct nlattr *allowedips_nest, *peer_nest = nla_nest_start(skb, 0);
	struct allowedips_node *allowedips_node = ctx->next_allowedip;
	bool fail;

	/* Start nested attribute for this peer */
	if (!peer_nest)
		return -EMSGSIZE;

	/* Add peer's public key (always required) */
	down_read(&peer->handshake.lock);
	fail = nla_put(skb, WGPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN,
		       peer->handshake.remote_static);
	up_read(&peer->handshake.lock);
	if (fail)
		goto err;

	/* If not resuming from allowed IPs dump, add all peer metadata */
	if (!allowedips_node) {
		/* Convert internal timestamp to kernel timespec format */
		const struct __kernel_timespec last_handshake = {
			.tv_sec = peer->walltime_last_handshake.tv_sec,
			.tv_nsec = peer->walltime_last_handshake.tv_nsec
		};

		/* Add pre-shared key */
		down_read(&peer->handshake.lock);
		fail = nla_put(skb, WGPEER_A_PRESHARED_KEY,
			       NOISE_SYMMETRIC_KEY_LEN,
			       peer->handshake.preshared_key);
		up_read(&peer->handshake.lock);
		if (fail)
			goto err;

		/* Add peer statistics and configuration */
		if (nla_put(skb, WGPEER_A_LAST_HANDSHAKE_TIME,
			    sizeof(last_handshake), &last_handshake) ||
		    nla_put_u16(skb, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
				peer->persistent_keepalive_interval) ||
		    nla_put_u64_64bit(skb, WGPEER_A_TX_BYTES, peer->tx_bytes,
				      WGPEER_A_UNSPEC) ||
		    nla_put_u64_64bit(skb, WGPEER_A_RX_BYTES, peer->rx_bytes,
				      WGPEER_A_UNSPEC) ||
		    nla_put_u32(skb, WGPEER_A_PROTOCOL_VERSION, 1))
			goto err;

		/* Add peer endpoint (IP address and port) */
		read_lock_bh(&peer->endpoint_lock);
		if (peer->endpoint.addr.sa_family == AF_INET)
			fail = nla_put(skb, WGPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr4),
				       &peer->endpoint.addr4);
		else if (peer->endpoint.addr.sa_family == AF_INET6)
			fail = nla_put(skb, WGPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr6),
				       &peer->endpoint.addr6);
		read_unlock_bh(&peer->endpoint_lock);
		if (fail)
			goto err;

		/* Get first allowed IP node for this peer */
		allowedips_node =
			list_first_entry_or_null(&peer->allowedips_list,
					struct allowedips_node, peer_list);
	}

	/* Skip allowed IPs if none exist */
	if (!allowedips_node)
		goto no_allowedips;

	/* Check sequence number for consistency during multi-part dumps */
	if (!ctx->allowedips_seq)
		ctx->allowedips_seq = peer->device->peer_allowedips.seq;
	else if (ctx->allowedips_seq != peer->device->peer_allowedips.seq)
		goto no_allowedips;  /* Allowed IPs changed during dump */

	/* Create nested attribute for allowed IPs list */
	allowedips_nest = nla_nest_start(skb, WGPEER_A_ALLOWEDIPS);
	if (!allowedips_nest)
		goto err;

	/* Iterate through allowed IPs, starting from where we left off */
	list_for_each_entry_from(allowedips_node, &peer->allowedips_list,
				 peer_list) {
		u8 cidr, ip[16] __aligned(__alignof(u64));
		int family;

		/* Extract IP address and CIDR from the allowed IPs node */
		family = wg_allowedips_read_node(allowedips_node, ip, &cidr);
		if (get_allowedips(skb, ip, cidr, family)) {
			/* If buffer is full, save our position for next dump */
			nla_nest_end(skb, allowedips_nest);
			nla_nest_end(skb, peer_nest);
			ctx->next_allowedip = allowedips_node;
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, allowedips_nest);

no_allowedips:
	/* Successfully completed this peer, finalize nested attributes */
	nla_nest_end(skb, peer_nest);
	ctx->next_allowedip = NULL;
	ctx->allowedips_seq = 0;
	return 0;

err:
	/* Error occurred, cancel the peer nested attribute */
	nla_nest_cancel(skb, peer_nest);
	return -EMSGSIZE;
}

/*
 * wg_get_device_start - Initialize netlink dump operation for a device
 * @cb: Netlink callback structure
 *
 * This function is called at the beginning of a netlink dump to initialize
 * the dump context with the target WireGuard device. It looks up the device
 * based on the netlink attributes and stores it in the dump context.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int wg_get_device_start(struct netlink_callback *cb)
{
	struct wg_device *wg;

	/* Look up the WireGuard device to dump */
	wg = lookup_interface(genl_dumpit_info(cb)->attrs, cb->skb);
	if (IS_ERR(wg))
		return PTR_ERR(wg);

	/* Store device in dump context for subsequent dump calls */
	DUMP_CTX(cb)->wg = wg;
	return 0;
}

/*
 * wg_get_device_dump - Main netlink dump function for device information
 * @skb: Socket buffer to write the netlink message to
 * @cb: Netlink callback containing dump state
 *
 * This function performs the actual dumping of WireGuard device and peer
 * information. It handles multi-part dumps by resuming from where the
 * previous dump left off when the message buffer becomes full.
 *
 * Returns: 0 when dump is complete, positive value for partial dumps,
 *          negative error code on failure
 */
static int wg_get_device_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct wg_peer *peer, *next_peer_cursor;
	struct dump_ctx *ctx = DUMP_CTX(cb);
	struct wg_device *wg = ctx->wg;
	struct nlattr *peers_nest;
	int ret = -EMSGSIZE;
	bool done = true;
	void *hdr;

	/* Acquire locks to ensure consistent state during dump */
	rtnl_lock();
	mutex_lock(&wg->device_update_lock);
	cb->seq = wg->device_update_gen;  /* Set sequence number for consistency */
	next_peer_cursor = ctx->next_peer;

	/* Create generic netlink message header */
	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &genl_family, NLM_F_MULTI, WG_CMD_GET_DEVICE);
	if (!hdr)
		goto out;
	genl_dump_check_consistent(cb, hdr);

	/* Add device attributes only on first dump call (not continuation) */
	if (!ctx->next_peer) {
		/* Add basic device configuration */
		if (nla_put_u16(skb, WGDEVICE_A_LISTEN_PORT,
				wg->incoming_port) ||
		    nla_put_u32(skb, WGDEVICE_A_FWMARK, wg->fwmark) ||
		    nla_put_u32(skb, WGDEVICE_A_IFINDEX, wg->dev->ifindex) ||
		    nla_put_string(skb, WGDEVICE_A_IFNAME, wg->dev->name))
			goto out;

		/* Add device identity (keys) if configured */
		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity) {
			if (nla_put(skb, WGDEVICE_A_PRIVATE_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    wg->static_identity.static_private) ||
			    nla_put(skb, WGDEVICE_A_PUBLIC_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    wg->static_identity.static_public)) {
				up_read(&wg->static_identity.lock);
				goto out;
			}
		}
		up_read(&wg->static_identity.lock);
	}

	/* Create nested attribute for peers list */
	peers_nest = nla_nest_start(skb, WGDEVICE_A_PEERS);
	if (!peers_nest)
		goto out;
	ret = 0;

	/*
	 * Handle edge case where peer was removed during dump.
	 * If the cursor peer was deleted, treat it as end of list.
	 * The sequence number change will signal userspace to retry.
	 */
	if (list_empty(&wg->peer_list) ||
	    (ctx->next_peer && list_empty(&ctx->next_peer->peer_list))) {
		nla_nest_cancel(skb, peers_nest);
		goto out;
	}

	/* Iterate through peers starting from where we left off */
	lockdep_assert_held(&wg->device_update_lock);
	peer = list_prepare_entry(ctx->next_peer, &wg->peer_list, peer_list);
	list_for_each_entry_continue(peer, &wg->peer_list, peer_list) {
		/* Try to add this peer to the message */
		if (get_peer(peer, skb, ctx)) {
			/* Buffer full, need to continue in next message */
			done = false;
			break;
		}
		/* Successfully added peer, update cursor */
		next_peer_cursor = peer;
	}
	nla_nest_end(skb, peers_nest);

out:
	/* Update peer reference counting for continuation */
	if (!ret && !done && next_peer_cursor)
		wg_peer_get(next_peer_cursor);  /* Take reference for next dump */
	wg_peer_put(ctx->next_peer);            /* Release previous reference */

	/* Release locks */
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();

	/* Handle message completion */
	if (ret) {
		genlmsg_cancel(skb, hdr);       /* Cancel partial message on error */
		return ret;
	}
	genlmsg_end(skb, hdr);                  /* Finalize message */

	if (done) {
		/* Dump complete, clear continuation state */
		ctx->next_peer = NULL;
		return 0;
	}

	/* Partial dump, save state for next call */
	ctx->next_peer = next_peer_cursor;
	return skb->len;  /* Return bytes written to continue dump */

	/*
	 * Security note: Private key material is included in the netlink message.
	 * Ideally, the kernel would provide an API to mark skbs as zero_on_free
	 * to securely clear this sensitive data after transmission.
	 */
}

/*
 * wg_get_device_done - Cleanup function called when netlink dump completes
 * @cb: Netlink callback structure
 *
 * This function is called when the netlink dump operation completes,
 * either successfully or due to an error. It cleans up any resources
 * allocated during the dump process.
 *
 * Returns: Always returns 0
 */
static int wg_get_device_done(struct netlink_callback *cb)
{
	struct dump_ctx *ctx = DUMP_CTX(cb);

	/* Release device reference if we have one */
	if (ctx->wg)
		dev_put(ctx->wg->dev);

	/* Release any remaining peer reference */
	wg_peer_put(ctx->next_peer);
	
	return 0;
}

/*
 * set_port - 更改 WireGuard 设备的 UDP 监听端口
 * @wg: 要配置的 WireGuard 设备
 * @port: 要监听的新 UDP 端口号
 *
 * 此函数更改 WireGuard 设备监听传入连接的 UDP 端口。
 * 当端口更改时，所有对等体端点源地址都会被清除，
 * 以确保在下次使用时重新解析。
 *
 * 返回值：成功时返回 0，失败时返回负错误码
 */
static int set_port(struct wg_device *wg, u16 port)
{
	struct wg_peer *peer;

	/* No change needed if port is already set to the requested value */
	if (wg->incoming_port == port)
		return 0;

	/* Clear all peer endpoint source addresses since port is changing */
	list_for_each_entry(peer, &wg->peer_list, peer_list)
		wg_socket_clear_peer_endpoint_src(peer);

	if (!netif_running(wg->dev)) {
		/* Device is down, just store the new port for later */
		wg->incoming_port = port;
		return 0;
	}

	/* Device is up, reinitialize socket with new port */
	return wg_socket_init(wg, port);
}

/*
 * set_allowedip - 向对等体添加允许的 IP 地址/子网
 * @peer: 要配置的 WireGuard 对等体
 * @attrs: 包含 IP 配置的 Netlink 属性
 *
 * 此函数向对等体的允许 IP 列表添加 IP 地址或子网。
 * 进出此列表中地址的流量将通过该对等体路由。
 * 函数在添加到设备路由表之前验证 IP 地址格式和 CIDR 范围。
 *
 * 返回值：成功时返回 0，失败时返回负错误码
 */
static int set_allowedip(struct wg_peer *peer, struct nlattr **attrs)
{
	int ret = -EINVAL;
	u16 family;
	u8 cidr;

	/* Validate that all required attributes are present */
	if (!attrs[WGALLOWEDIP_A_FAMILY] || !attrs[WGALLOWEDIP_A_IPADDR] ||
	    !attrs[WGALLOWEDIP_A_CIDR_MASK])
		return ret;

	family = nla_get_u16(attrs[WGALLOWEDIP_A_FAMILY]);
	cidr = nla_get_u8(attrs[WGALLOWEDIP_A_CIDR_MASK]);

	/* Handle IPv4 addresses */
	if (family == AF_INET && cidr <= 32 &&
	    nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in_addr))
		ret = wg_allowedips_insert_v4(
			&peer->device->peer_allowedips,
			nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer,
			&peer->device->device_update_lock);
	/* Handle IPv6 addresses */
	else if (family == AF_INET6 && cidr <= 128 &&
		 nla_len(attrs[WGALLOWEDIP_A_IPADDR]) == sizeof(struct in6_addr))
		ret = wg_allowedips_insert_v6(
			&peer->device->peer_allowedips,
			nla_data(attrs[WGALLOWEDIP_A_IPADDR]), cidr, peer,
			&peer->device->device_update_lock);

	return ret;
}

/*
 * set_peer - 配置或管理 WireGuard 对等体
 * @wg: 要配置的 WireGuard 设备
 * @attrs: 包含对等体配置的 Netlink 属性
 *
 * 这是处理创建、更新和删除对等体的主要对等体管理函数。
 * 它处理所有与对等体相关的 netlink 属性，包括公钥、预共享密钥、
 * 端点、允许的 IP 和保活设置。
 *
 * 返回值：成功时返回 0，失败时返回负错误码
 */
static int set_peer(struct wg_device *wg, struct nlattr **attrs)
{
	u8 *public_key = NULL, *preshared_key = NULL;
	struct wg_peer *peer = NULL;
	u32 flags = 0;
	int ret;

	/* Public key is mandatory for all peer operations */
	ret = -EINVAL;
	if (attrs[WGPEER_A_PUBLIC_KEY] &&
	    nla_len(attrs[WGPEER_A_PUBLIC_KEY]) == NOISE_PUBLIC_KEY_LEN)
		public_key = nla_data(attrs[WGPEER_A_PUBLIC_KEY]);
	else
		goto out;

	/* Pre-shared key is optional but must be correct length if present */
	if (attrs[WGPEER_A_PRESHARED_KEY] &&
	    nla_len(attrs[WGPEER_A_PRESHARED_KEY]) == NOISE_SYMMETRIC_KEY_LEN)
		preshared_key = nla_data(attrs[WGPEER_A_PRESHARED_KEY]);

	/* Extract and validate configuration flags */
	if (attrs[WGPEER_A_FLAGS])
		flags = nla_get_u32(attrs[WGPEER_A_FLAGS]);
	ret = -EOPNOTSUPP;
	if (flags & ~__WGPEER_F_ALL)
		goto out;  /* Invalid flags provided */

	/* Check protocol version compatibility */
	ret = -EPFNOSUPPORT;
	if (attrs[WGPEER_A_PROTOCOL_VERSION]) {
		if (nla_get_u32(attrs[WGPEER_A_PROTOCOL_VERSION]) != 1)
			goto out;  /* Only protocol version 1 is supported */
	}

	/* Look up existing peer by public key */
	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable,
					  nla_data(attrs[WGPEER_A_PUBLIC_KEY]));
	ret = 0;

	if (!peer) {
		/* Peer doesn't exist yet, create a new one */
		/* Can't remove or update-only a peer that doesn't exist */
		if (flags & (WGPEER_F_REMOVE_ME | WGPEER_F_UPDATE_ONLY))
			goto out;

		/* New peer, so no existing allowed IPs to replace */
		flags &= ~WGPEER_F_REPLACE_ALLOWEDIPS;

		/* Prevent adding peer with same public key as device */
		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity &&
		    !memcmp(nla_data(attrs[WGPEER_A_PUBLIC_KEY]),
			    wg->static_identity.static_public,
			    NOISE_PUBLIC_KEY_LEN)) {
			/*
			 * Silently ignore self-peer to allow reusing the same
			 * configuration across different devices without errors.
			 */
			up_read(&wg->static_identity.lock);
			ret = 0;
			goto out;
		}
		up_read(&wg->static_identity.lock);

		/* Create the new peer */
		peer = wg_peer_create(wg, public_key, preshared_key);
		if (IS_ERR(peer)) {
			ret = PTR_ERR(peer);
			peer = NULL;
			goto out;
		}

		/* Take additional reference to match lookup behavior */
		wg_peer_get(peer);
	}

	/* Handle peer removal request */
	if (flags & WGPEER_F_REMOVE_ME) {
		wg_peer_remove(peer);
		goto out;
	}

	/* Update pre-shared key if provided */
	if (preshared_key) {
		down_write(&peer->handshake.lock);
		memcpy(&peer->handshake.preshared_key, preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
		up_write(&peer->handshake.lock);
	}

	/* Update peer endpoint (IP address and port) */
	if (attrs[WGPEER_A_ENDPOINT]) {
		struct sockaddr *addr = nla_data(attrs[WGPEER_A_ENDPOINT]);
		size_t len = nla_len(attrs[WGPEER_A_ENDPOINT]);

		/* Validate endpoint address family and size */
		if ((len == sizeof(struct sockaddr_in) &&
		     addr->sa_family == AF_INET) ||
		    (len == sizeof(struct sockaddr_in6) &&
		     addr->sa_family == AF_INET6)) {
			struct endpoint endpoint = { { { 0 } } };

			memcpy(&endpoint.addr, addr, len);
			wg_socket_set_peer_endpoint(peer, &endpoint);
		}
	}

	/* Clear existing allowed IPs if replacement flag is set */
	if (flags & WGPEER_F_REPLACE_ALLOWEDIPS)
		wg_allowedips_remove_by_peer(&wg->peer_allowedips, peer,
					     &wg->device_update_lock);

	/* Process nested allowed IPs list */
	if (attrs[WGPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr, *allowedip[WGALLOWEDIP_A_MAX + 1];
		int rem;

		/* Iterate through each allowed IP entry */
		nla_for_each_nested(attr, attrs[WGPEER_A_ALLOWEDIPS], rem) {
			ret = nla_parse_nested(allowedip, WGALLOWEDIP_A_MAX,
					       attr, allowedip_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_allowedip(peer, allowedip);
			if (ret < 0)
				goto out;
		}
	}

	/* Update persistent keepalive interval */
	if (attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
		const u16 persistent_keepalive_interval = nla_get_u16(
				attrs[WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		const bool send_keepalive =
			!peer->persistent_keepalive_interval &&
			persistent_keepalive_interval &&
			netif_running(wg->dev);

		peer->persistent_keepalive_interval = persistent_keepalive_interval;
		/* Send immediate keepalive if enabling for the first time */
		if (send_keepalive)
			wg_packet_send_keepalive(peer);
	}

	/* Send any packets that were queued while peer was being configured */
	if (netif_running(wg->dev))
		wg_packet_send_staged_packets(peer);

out:
	/* Release peer reference acquired during configuration */
	wg_peer_put(peer);

	/* Securely clear pre-shared key from memory */
	if (attrs[WGPEER_A_PRESHARED_KEY])
		memzero_explicit(nla_data(attrs[WGPEER_A_PRESHARED_KEY]),
				 nla_len(attrs[WGPEER_A_PRESHARED_KEY]));
	return ret;
}

/*
 * wg_set_device - 配置 WireGuard 设备设置和对等体
 * @skb: 包含 netlink 请求的套接字缓冲区
 * @info: 包含已解析属性的通用 netlink 信息结构
 *
 * 这是 WireGuard 设备的主要配置函数。它处理设备级参数
 * （端口、fwmark、私钥）的设置和对等体列表的管理。
 * 操作需要适当的网络管理权限。
 *
 * 返回值：成功时返回 0，失败时返回负错误码
 */
static int wg_set_device(struct sk_buff *skb, struct genl_info *info)
{
	struct wg_device *wg = lookup_interface(info->attrs, skb);
	u32 flags = 0;
	int ret;

	/* Validate that we found a valid WireGuard device */
	if (IS_ERR(wg)) {
		ret = PTR_ERR(wg);
		goto out_nodev;
	}

	/* Acquire locks to ensure atomic device configuration */
	rtnl_lock();
	mutex_lock(&wg->device_update_lock);

	/* Extract and validate configuration flags */
	if (info->attrs[WGDEVICE_A_FLAGS])
		flags = nla_get_u32(info->attrs[WGDEVICE_A_FLAGS]);
	ret = -EOPNOTSUPP;
	if (flags & ~__WGDEVICE_F_ALL)
		goto out;  /* Invalid flags provided */

	/* Check network administration capabilities for privileged operations */
	if (info->attrs[WGDEVICE_A_LISTEN_PORT] || info->attrs[WGDEVICE_A_FWMARK]) {
		struct net *net;
		rcu_read_lock();
		net = rcu_dereference(wg->creating_net);
		ret = !net || !ns_capable(net->user_ns, CAP_NET_ADMIN) ? -EPERM : 0;
		rcu_read_unlock();
		if (ret)
			goto out;
	}

	/* Increment generation counter to invalidate concurrent dumps */
	++wg->device_update_gen;

	/* Update firewall mark (affects SO_MARK on outgoing packets) */
	if (info->attrs[WGDEVICE_A_FWMARK]) {
		struct wg_peer *peer;

		wg->fwmark = nla_get_u32(info->attrs[WGDEVICE_A_FWMARK]);
		/* Clear peer endpoint source addresses since fwmark changed */
		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_socket_clear_peer_endpoint_src(peer);
	}

	/* Update UDP listening port */
	if (info->attrs[WGDEVICE_A_LISTEN_PORT]) {
		ret = set_port(wg,
			nla_get_u16(info->attrs[WGDEVICE_A_LISTEN_PORT]));
		if (ret)
			goto out;
	}

	/* Remove all existing peers if replacement flag is set */
	if (flags & WGDEVICE_F_REPLACE_PEERS)
		wg_peer_remove_all(wg);

	/* Update device private key and regenerate public key */
	if (info->attrs[WGDEVICE_A_PRIVATE_KEY] &&
	    nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]) ==
		    NOISE_PUBLIC_KEY_LEN) {
		u8 *private_key = nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]);
		u8 public_key[NOISE_PUBLIC_KEY_LEN];
		struct wg_peer *peer, *temp;

		/* Skip if the private key hasn't actually changed */
		if (!crypto_memneq(wg->static_identity.static_private,
				   private_key, NOISE_PUBLIC_KEY_LEN))
			goto skip_set_private_key;

		/*
		 * Remove any peer that has the same public key as our new key.
		 * This prevents self-peering. We do this before setting the key
		 * to avoid race conditions, though it means generating the public
		 * key twice.
		 */
		if (curve25519_generate_public(public_key, private_key)) {
			peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable,
							  public_key);
			if (peer) {
				wg_peer_put(peer);
				wg_peer_remove(peer);
			}
		}

		/* Atomically update the device identity and all peer relationships */
		down_write(&wg->static_identity.lock);
		wg_noise_set_static_identity_private_key(&wg->static_identity,
							 private_key);
		/* Recompute shared secrets with all existing peers */
		list_for_each_entry_safe(peer, temp, &wg->peer_list,
					 peer_list) {
			wg_noise_precompute_static_static(peer);
			wg_noise_expire_current_peer_keypairs(peer);
		}
		/* Update cookie checker with new device keys */
		wg_cookie_checker_precompute_device_keys(&wg->cookie_checker);
		up_write(&wg->static_identity.lock);
	}
skip_set_private_key:

	/* Process nested peers configuration */
	if (info->attrs[WGDEVICE_A_PEERS]) {
		struct nlattr *attr, *peer[WGPEER_A_MAX + 1];
		int rem;

		/* Iterate through each peer entry */
		nla_for_each_nested(attr, info->attrs[WGDEVICE_A_PEERS], rem) {
			ret = nla_parse_nested(peer, WGPEER_A_MAX, attr,
					       peer_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_peer(wg, peer);
			if (ret < 0)
				goto out;
		}
	}
	ret = 0;  /* Success */

out:
	/* Release locks and device reference */
	mutex_unlock(&wg->device_update_lock);
	rtnl_unlock();
	dev_put(wg->dev);
out_nodev:
	/* Securely clear private key from memory */
	if (info->attrs[WGDEVICE_A_PRIVATE_KEY])
		memzero_explicit(nla_data(info->attrs[WGDEVICE_A_PRIVATE_KEY]),
				 nla_len(info->attrs[WGDEVICE_A_PRIVATE_KEY]));
	return ret;
}

/*
 * 通用 netlink 操作表
 * 定义 WireGuard netlink 族可用的命令及其处理程序
 */
#ifndef COMPAT_CANNOT_USE_CONST_GENL_OPS
static const
#else
static
#endif
struct genl_ops genl_ops[] = {
	{
		/* WG_CMD_GET_DEVICE - 检索设备配置和对等体状态 */
		.cmd = WG_CMD_GET_DEVICE,
#ifndef COMPAT_CANNOT_USE_NETLINK_START
		.start = wg_get_device_start,        /* 初始化转储操作 */
#endif
		.dumpit = wg_get_device_dump,        /* 主转储函数 */
		.done = wg_get_device_done,          /* 转储后清理 */
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,             /* 验证策略 */
#endif
		.flags = GENL_UNS_ADMIN_PERM         /* 需要网络管理员权限 */
	}, {
		/* WG_CMD_SET_DEVICE - 配置设备设置和对等体 */
		.cmd = WG_CMD_SET_DEVICE,
		.doit = wg_set_device,               /* 配置处理程序 */
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,             /* 验证策略 */
#endif
		.flags = GENL_UNS_ADMIN_PERM         /* 需要网络管理员权限 */
	}
};

/*
 * 通用 netlink 族定义
 * 此结构定义了 WireGuard netlink 族及其属性
 */
static struct genl_family genl_family
#ifndef COMPAT_CANNOT_USE_GENL_NOPS
__ro_after_init = {
	.ops = genl_ops,                         /* 操作表 */
	.n_ops = ARRAY_SIZE(genl_ops),           /* 操作数量 */
#else
= {
#endif
	.name = WG_GENL_NAME,                    /* 族名称 "wireguard" */
	.version = WG_GENL_VERSION,              /* 协议版本 */
	.maxattr = WGDEVICE_A_MAX,               /* 最大属性 ID */
	.module = THIS_MODULE,                   /* 拥有的内核模块 */
#ifndef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
	.policy = device_policy,                 /* 默认验证策略 */
#endif
	.netnsok = true                          /* 支持网络命名空间 */
};

/*
 * wg_genetlink_init - 初始化 WireGuard 通用 netlink 接口
 * 
 * 在模块初始化期间调用，将 netlink 族注册到内核的
 * 通用 netlink 子系统。
 *
 * 返回值：成功时返回 0，失败时返回负错误码
 */
int __init wg_genetlink_init(void)
{
	return genl_register_family(&genl_family);
}

/*
 * wg_genetlink_uninit - 清理 WireGuard 通用 netlink 接口
 *
 * 在模块退出时调用，注销 netlink 族并清理资源。
 */
void __exit wg_genetlink_uninit(void)
{
	genl_unregister_family(&genl_family);
}
