// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * ===================================================================
 * WireGuard 数据包接收处理引擎
 * ===================================================================
 * 
 * 本文件实现了 WireGuard VPN 的完整数据包接收处理流程，包括：
 * 1. 握手包处理 (Handshake Packets)
 * 2. 数据包解密 (Data Packet Decryption)  
 * 3. 重放攻击防护 (Anti-replay Protection)
 * 4. 包转发和路由验证 (Packet Forwarding & Route Validation)
 * 5. 性能优化和负载均衡 (Performance & Load Balancing)
 * 
 * 整体数据流架构：
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    WireGuard 接收处理流水线                      │
 * ├─────────────────────────────────────────────────────────────────┤
 * │                                                                 │
 * │  网络接口                    包分类器                            │
 * │     │                          │                               │
 * │     ▼                          ▼                               │
 * │ ┌─────────┐    ┌─────────────────────────────────────────┐     │
 * │ │UDP包接收│ ──→ │      wg_packet_receive()             │     │
 * │ │Raw Packet│    │   • 包头验证和解析                    │     │
 * │ └─────────┘    │   • 消息类型识别                      │     │
 * │                │   • 队列分发决策                      │     │
 * │                └─────────────────────────────────────────┘     │
 * │                          │                                     │
 * │                          ▼                                     │
 * │          ┌─────────────────────────────────────┐               │
 * │          │            消息类型路由              │               │
 * │          └─────────────────────────────────────┘               │
 * │                │               │                               │
 * │       握手消息  │               │  数据消息                     │
 * │                ▼               ▼                               │
 * │  ┌───────────────────┐    ┌──────────────────┐                │
 * │  │   握手处理队列     │    │   解密处理队列    │                │
 * │  │ Handshake Queue   │    │  Decrypt Queue   │                │
 * │  │                  │    │                  │                │
 * │  │ • Cookie验证      │    │ • 密钥查找       │                │
 * │  │ • 负载控制        │    │ • 包解密         │                │
 * │  │ • 异步处理        │    │ • 重放检测       │                │
 * │  └───────────────────┘    └──────────────────┘                │
 * │           │                       │                           │
 * │           ▼                       ▼                           │
 * │  ┌───────────────────┐    ┌──────────────────┐                │
 * │  │  握手状态更新      │    │   包转发处理     │                │
 * │  │                  │    │                  │                │
 * │  │ • 密钥协商        │    │ • 路由验证       │                │
 * │  │ • 会话建立        │    │ • QoS处理        │                │
 * │  │ • 定时器更新      │    │ • 网络栈投递     │                │
 * │  └───────────────────┘    └──────────────────┘                │
 * └─────────────────────────────────────────────────────────────────┘
 * 
 * 性能特性：
 * 1. 多核并行处理 - 握手和解密分布在多个CPU核心
 * 2. SIMD加速解密 - 利用CPU向量指令加速ChaCha20Poly1305
 * 3. 零拷贝优化 - 最小化内存拷贝操作
 * 4. 自适应负载均衡 - 动态分配工作负载到可用CPU
 * 5. 拥塞控制 - 防止队列溢出和DoS攻击
 * 
 * 安全特性：
 * 1. RFC6479重放攻击防护 - 滑动窗口位图算法
 * 2. 严格的包验证 - 多层次完整性检查
 * 3. 时间导向的密钥管理 - 自动密钥轮换
 * 4. IP路由验证 - 防止IP源地址欺骗
 * 5. 拥塞控制 - 防止资源耗尽攻击
 */

#include "queueing.h"
#include "device.h"
#include "peer.h"
#include "timers.h"
#include "messages.h"
#include "cookie.h"
#include "socket.h"

#include <linux/simd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>

/*
 * ===================================================================
 * 统计信息更新函数
 * ===================================================================
 */

/**
 * update_rx_stats - 更新接收数据包统计信息
 * @peer: 目标对等体指针
 * @len: 接收的数据包长度
 * 
 * 功能描述：
 * 更新设备和对等体级别的接收统计信息，包括包计数和字节计数。
 * 使用per-CPU统计结构优化多核性能。
 * 
 * 统计更新流程：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     统计信息更新                             │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  1. 获取当前CPU的统计结构                                   │
 * │     └── get_cpu_ptr() - 禁用抢占并获取per-CPU数据           │
 * │                                                             │
 * │  2. 开始原子更新序列                                        │
 * │     └── u64_stats_update_begin() - 防止读写竞争             │
 * │                                                             │
 * │  3. 更新统计计数器                                          │
 * │     ├── tstats->rx_packets++  (设备级包计数)                │
 * │     ├── tstats->rx_bytes += len  (设备级字节计数)            │
 * │     └── peer->rx_bytes += len  (对等体级字节计数)            │
 * │                                                             │
 * │  4. 结束原子更新序列                                        │
 * │     └── u64_stats_update_end() - 释放更新锁                 │
 * │                                                             │
 * │  5. 释放CPU统计结构                                         │
 * │     └── put_cpu_ptr() - 重新启用抢占                        │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 并发控制：
 * - 必须在底半部禁用状态下调用 (bh disabled)
 * - 使用u64_stats序列锁防止读写竞争
 * - per-CPU数据结构减少锁竞争
 * 
 * 性能考虑：
 * - get_cpu_ptr()禁用抢占，确保在同一CPU上执行
 * - per-CPU统计避免跨CPU缓存行竞争
 * - 原子更新序列保证统计一致性
 */
/* Must be called with bh disabled. */
static void update_rx_stats(struct wg_peer *peer, size_t len)
{
	struct pcpu_sw_netstats *tstats =
		get_cpu_ptr(peer->device->dev->tstats);  /* 获取当前CPU的网络统计结构 */

	u64_stats_update_begin(&tstats->syncp);     /* 开始原子统计更新 */
	++tstats->rx_packets;                       /* 增加接收包计数 */
	tstats->rx_bytes += len;                    /* 增加设备接收字节数 */
	peer->rx_bytes += len;                      /* 增加对等体接收字节数 */
	u64_stats_update_end(&tstats->syncp);       /* 结束原子统计更新 */
	put_cpu_ptr(tstats);                        /* 释放CPU统计结构，重新启用抢占 */
}

/*
 * ===================================================================
 * 消息头部验证和解析函数
 * ===================================================================
 */

/**
 * SKB_TYPE_LE32 - 提取数据包中的消息类型 (小端序)
 * @skb: 网络数据包结构指针
 * 
 * 宏定义说明：
 * 快速提取 sk_buff 数据中 WireGuard 消息头的类型字段。
 * 消息类型以小端序格式存储在包的开头。
 * 
 * 消息头结构：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    WireGuard 消息头格式                      │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  字节偏移    字段名        长度      描述                    │
 * │     0       type           4       消息类型 (小端序)         │
 * │     4       reserved       3       保留字段 (必须为0)        │
 * │     7       ...            ...     消息特定内容               │
 * │                                                             │
 * │  消息类型常量：                                              │
 * │  • MESSAGE_DATA = 4                (数据包)                 │
 * │  • MESSAGE_HANDSHAKE_INITIATION = 1 (握手初始化)            │
 * │  • MESSAGE_HANDSHAKE_RESPONSE = 2   (握手响应)              │
 * │  • MESSAGE_HANDSHAKE_COOKIE = 3     (握手Cookie)            │
 * └─────────────────────────────────────────────────────────────┘
 */
#define SKB_TYPE_LE32(skb) (((struct message_header *)(skb)->data)->type)

/**
 * validate_header_len - 验证WireGuard消息头长度和类型
 * @skb: 网络数据包结构指针
 * 
 * 返回值：有效消息的头部长度，失败时返回0
 * 
 * 功能描述：
 * 根据消息类型验证数据包长度是否正确，确保包含完整的消息头。
 * 这是接收处理的第一道安全检查。
 * 
 * 验证逻辑流程：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                  消息头验证决策树                            │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  输入：sk_buff                                              │
 * │     │                                                       │
 * │     ▼                                                       │
 * │  长度 >= sizeof(message_header) ?                           │
 * │     │                 │                                     │
 * │   否 │                │ 是                                  │
 * │     ▼                 ▼                                     │
 * │  返回0           提取消息类型                                │
 * │                       │                                     │
 * │                       ▼                                     │
 * │          ┌─────────────────────────────┐                   │
 * │          │      消息类型分支判断        │                   │
 * │          └─────────────────────────────┘                   │
 * │                       │                                     │
 * │        ┌──────────────┼──────────────┐                     │
 * │        ▼              ▼              ▼                     │
 * │   DATA包        握手INITIATION   握手RESPONSE               │
 * │ len>=MIN_LEN?   len==INIT_LEN?   len==RESP_LEN?            │
 * │        │              │              │                     │
 * │        ▼              ▼              ▼                     │
 * │  返回DATA_LEN    返回INIT_LEN    返回RESP_LEN               │
 * │                                                             │
 * │        ┌──────────────┐                                    │
 * │        ▼              ▼                                     │
 * │   握手COOKIE     未知类型                                   │
 * │ len==COOKIE_LEN?     │                                     │
 * │        │             ▼                                     │
 * │        ▼           返回0                                   │
 * │  返回COOKIE_LEN                                            │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 安全考虑：
 * 1. 严格的长度检查防止缓冲区溢出
 * 2. 数据包类型必须精确匹配预期长度
 * 3. 拒绝畸形或截断的包
 * 4. 为后续处理提供长度保证
 * 
 * 消息类型和长度对应表：
 * ┌─────────────────────────┬─────────────┬─────────────────┐
 * │       消息类型          │    常量值   │    期望长度      │
 * ├─────────────────────────┼─────────────┼─────────────────┤
 * │ MESSAGE_DATA            │      4      │ >= MIN_LENGTH   │
 * │ MESSAGE_HANDSHAKE_INIT  │      1      │ == INIT_SIZE    │
 * │ MESSAGE_HANDSHAKE_RESP  │      2      │ == RESP_SIZE    │
 * │ MESSAGE_HANDSHAKE_COOKIE│      3      │ == COOKIE_SIZE  │
 * └─────────────────────────┴─────────────┴─────────────────┘
 */
static size_t validate_header_len(struct sk_buff *skb)
{
	/* 基本长度检查：确保包含基本消息头 */
	if (unlikely(skb->len < sizeof(struct message_header)))
		return 0;
		
	/* 数据包：变长，但有最小长度要求 */
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_DATA) &&
	    skb->len >= MESSAGE_MINIMUM_LENGTH)
		return sizeof(struct message_data);
		
	/* 握手初始化包：固定长度 */
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) &&
	    skb->len == sizeof(struct message_handshake_initiation))
		return sizeof(struct message_handshake_initiation);
		
	/* 握手响应包：固定长度 */
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) &&
	    skb->len == sizeof(struct message_handshake_response))
		return sizeof(struct message_handshake_response);
		
	/* 握手Cookie包：固定长度 */
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE) &&
	    skb->len == sizeof(struct message_handshake_cookie))
		return sizeof(struct message_handshake_cookie);
		
	/* 未知消息类型或长度不匹配 */
	return 0;
}

/**
 * prepare_skb_header - 准备和验证sk_buff的UDP/WireGuard头部
 * @skb: 网络数据包结构指针
 * @wg: WireGuard设备结构指针
 * 
 * 返回值：成功时返回0，失败时返回负数错误码
 * 
 * 功能描述：
 * 对接收到的网络包进行深度验证和预处理，确保UDP头和WireGuard消息头
 * 的完整性和合法性，为后续的消息解析做准备。
 * 
 * 数据包结构验证流程：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                   网络包结构验证                             │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  原始网络包结构：                                           │
 * │  ┌─────────┬─────────┬─────────┬───────────────┐            │
 * │  │ ETH HDR │ IP HDR  │ UDP HDR │ WireGuard MSG │            │
 * │  └─────────┴─────────┴─────────┴───────────────┘            │
 * │                                                             │
 * │  处理步骤：                                                 │
 * │  1. 协议类型检查 (IPv4/IPv6 + UDP)                         │
 * │  2. 传输层头部边界验证                                      │
 * │  3. UDP头部完整性检查                                       │
 * │  4. UDP长度字段验证                                         │
 * │  5. WireGuard消息头提取和验证                               │
 * │  6. 数据包边界调整和内存优化                                │
 * │                                                             │
 * │  内存布局调整：                                             │
 * │  调整前：[ETH][IP][UDP][WG_MSG]                             │
 * │  调整后：      [WG_MSG]    (skb->data指向WG消息开始)        │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 验证检查点：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     安全检查清单                             │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  ✓ 协议栈检查：                                             │
 * │    • wg_check_packet_protocol() - IP协议验证                │
 * │    • 确保是IPv4或IPv6 + UDP组合                             │
 * │                                                             │
 * │  ✓ 边界检查：                                               │
 * │    • transport_header在有效范围内                           │
 * │    • UDP头不超出包末尾                                      │
 * │    • data_offset不超过U16_MAX                               │
 * │                                                             │
 * │  ✓ 长度一致性：                                             │
 * │    • UDP长度字段 >= sizeof(udphdr)                          │
 * │    • UDP声明长度 <= 实际可用长度                            │
 * │    • 最终包长度与计算长度一致                                │
 * │                                                             │
 * │  ✓ 内存安全：                                               │
 * │    • pskb_may_pull()确保内存可访问性                        │
 * │    • pskb_trim()安全截断多余数据                            │
 * │    • WireGuard消息头完整性                                  │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 错误处理场景：
 * - 协议类型不匹配 (非UDP包)
 * - 头部指针越界或损坏
 * - UDP长度字段异常
 * - 内存不足或分配失败
 * - WireGuard消息格式错误
 * 
 * 性能优化：
 * - 使用 unlikely() 标记错误路径
 * - 最小化内存拷贝操作
 * - 就地调整skb指针避免数据移动
 */
static int prepare_skb_header(struct sk_buff *skb, struct wg_device *wg)
{
	size_t data_offset, data_len, header_len;
	struct udphdr *udp;

	/* 第一层验证：基本协议和传输层头部检查 */
	if (unlikely(!wg_check_packet_protocol(skb) ||               /* 协议类型验证 */
		     skb_transport_header(skb) < skb->head ||            /* 头部指针边界检查 */
		     (skb_transport_header(skb) + sizeof(struct udphdr)) >
			     skb_tail_pointer(skb)))                     /* UDP头部不越界 */
		return -EINVAL; /* Bogus IP header - 无效的IP头部 */
		
	/* 获取UDP头部并计算数据偏移 */
	udp = udp_hdr(skb);
	data_offset = (u8 *)udp - skb->data;
	
	/* 第二层验证：UDP头部位置和可访问性检查 */
	if (unlikely(data_offset > U16_MAX ||                        /* 偏移量不能超过16位最大值 */
		     data_offset + sizeof(struct udphdr) > skb->len))   /* UDP头必须完全在包内 */
		/* Packet has offset at impossible location or isn't big enough
		 * to have UDP fields.
		 * 数据包偏移位置不可能或者不够大无法包含UDP字段
		 */
		return -EINVAL;
		
	/* 第三层验证：UDP长度字段一致性检查 */
	data_len = ntohs(udp->len);                                  /* 获取UDP长度 (网络字节序转主机序) */
	if (unlikely(data_len < sizeof(struct udphdr) ||            /* UDP长度至少要包含UDP头 */
		     data_len > skb->len - data_offset))                /* UDP长度不能超过实际可用空间 */
		/* UDP packet is reporting too small of a size or lying about
		 * its size.
		 * UDP包报告的大小太小或者在撒谎关于它的大小
		 */
		return -EINVAL;
		
	/* 调整为WireGuard载荷长度和偏移 */
	data_len -= sizeof(struct udphdr);                          /* 减去UDP头长度，得到实际载荷长度 */
	data_offset = (u8 *)udp + sizeof(struct udphdr) - skb->data;/* 计算WireGuard消息开始位置 */
	
	/* 第四层验证：内存可访问性和包修整 */
	if (unlikely(!pskb_may_pull(skb,                            /* 确保消息头可访问 */
				data_offset + sizeof(struct message_header)) ||
		     pskb_trim(skb, data_len + data_offset) < 0))       /* 修整包到正确长度 */
		return -EINVAL;
		
	/* 调整skb->data指针到WireGuard消息开始位置 */
	skb_pull(skb, data_offset);
	
	/* 第五层验证：最终长度一致性检查 */
	if (unlikely(skb->len != data_len))
		/* Final len does not agree with calculated len
		 * 最终长度与计算长度不一致
		 */
		return -EINVAL;
		
	/* 第六层验证：WireGuard消息头验证 */
	header_len = validate_header_len(skb);                      /* 验证WireGuard消息头 */
	if (unlikely(!header_len))
		return -EINVAL;
		
	/* 临时恢复完整包结构进行最终验证 */
	__skb_push(skb, data_offset);                               /* 恢复到包开头 */
	if (unlikely(!pskb_may_pull(skb, data_offset + header_len)))/* 确保完整头部可访问 */
		return -EINVAL;
	__skb_pull(skb, data_offset);                               /* 重新调整到WireGuard消息位置 */
	
	return 0;                                                   /* 验证成功 */
}

static void wg_receive_handshake_packet(struct wg_device *wg,
					struct sk_buff *skb)
{
	enum cookie_mac_state mac_state;
	struct wg_peer *peer = NULL;
	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static u64 last_under_load;
	bool packet_needs_cookie;
	bool under_load;

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE)) {
		net_dbg_skb_ratelimited("%s: Receiving cookie response from %pISpfsc\n",
					wg->dev->name, skb);
		wg_cookie_message_consume(
			(struct message_handshake_cookie *)skb->data, wg);
		return;
	}

	under_load = atomic_read(&wg->handshake_queue_len) >=
			MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load) {
		last_under_load = ktime_get_coarse_boottime_ns();
	} else if (last_under_load) {
		under_load = !wg_birthdate_has_expired(last_under_load, 1);
		if (!under_load)
			last_under_load = 0;
	}
	mac_state = wg_cookie_validate_packet(&wg->cookie_checker, skb,
					      under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
	    (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)) {
		packet_needs_cookie = false;
	} else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE) {
		packet_needs_cookie = true;
	} else {
		net_dbg_skb_ratelimited("%s: Invalid MAC of handshake, dropping packet from %pISpfsc\n",
					wg->dev->name, skb);
		return;
	}

	switch (SKB_TYPE_LE32(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION): {
		struct message_handshake_initiation *message =
			(struct message_handshake_initiation *)skb->data;

		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb,
							message->sender_index);
			return;
		}
		peer = wg_noise_handshake_consume_initiation(message, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake initiation from %pISpfsc\n",
						wg->dev->name, skb);
			return;
		}
		wg_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake initiation from peer %llu (%pISpfsc)\n",
				    wg->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		wg_packet_send_handshake_response(peer);
		break;
	}
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE): {
		struct message_handshake_response *message =
			(struct message_handshake_response *)skb->data;

		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb,
							message->sender_index);
			return;
		}
		peer = wg_noise_handshake_consume_response(message, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake response from %pISpfsc\n",
						wg->dev->name, skb);
			return;
		}
		wg_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake response from peer %llu (%pISpfsc)\n",
				    wg->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_handshake_complete(peer);
			/* Calling this function will either send any existing
			 * packets in the queue and not send a keepalive, which
			 * is the best case, Or, if there's nothing in the
			 * queue, it will send a keepalive, in order to give
			 * immediate confirmation of the session.
			 */
			wg_packet_send_keepalive(peer);
		}
		break;
	}
	}

	if (unlikely(!peer)) {
		WARN(1, "Somehow a wrong type of packet wound up in the handshake queue!\n");
		return;
	}

	local_bh_disable();
	update_rx_stats(peer, skb->len);
	local_bh_enable();

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);
	wg_peer_put(peer);
}

void wg_packet_handshake_receive_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker, work)->ptr;
	struct wg_device *wg = container_of(queue, struct wg_device, handshake_queue);
	struct sk_buff *skb;

	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		wg_receive_handshake_packet(wg, skb);
		dev_kfree_skb(skb);
		atomic_dec(&wg->handshake_queue_len);
		cond_resched();
	}
}

static void keep_key_fresh(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	bool send;

	if (peer->sent_lastminute_handshake)
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       keypair->i_am_the_initiator &&
	       wg_birthdate_has_expired(keypair->sending.birthdate,
			REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT);
	rcu_read_unlock_bh();

	if (unlikely(send)) {
		peer->sent_lastminute_handshake = true;
		wg_packet_send_queued_handshake_initiation(peer, false);
	}
}

static bool decrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair,
			   simd_context_t *simd_context)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	if (unlikely(!keypair))
		return false;

	if (unlikely(!READ_ONCE(keypair->receiving.is_valid) ||
		  wg_birthdate_has_expired(keypair->receiving.birthdate, REJECT_AFTER_TIME) ||
		  keypair->receiving_counter.counter >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->receiving.is_valid, false);
		return false;
	}

	PACKET_CB(skb)->nonce =
		le64_to_cpu(((struct message_data *)skb->data)->counter);

	/* We ensure that the network header is part of the packet before we
	 * call skb_cow_data, so that there's no chance that data is removed
	 * from the skb, so that later we can extract the original endpoint.
	 */
	offset = skb->data - skb_network_header(skb);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg_inplace(sg, skb->len, NULL, 0,
						 PACKET_CB(skb)->nonce,
						 keypair->receiving.key,
						 simd_context))
		return false;

	/* Another ugly situation of pushing and pulling the header so as to
	 * keep endpoint information intact.
	 */
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0)))
		return false;
	skb_pull(skb, offset);

	return true;
}

/*
 * ===================================================================
 * RFC6479 重放攻击防护算法
 * ===================================================================
 */

/**
 * counter_validate - RFC6479重放检测位图算法实现
 * @counter: 重放计数器结构指针
 * @their_counter: 对方发送的包序列号
 * 
 * 返回值：true表示包有效(未重放)，false表示包重放或无效
 * 
 * 功能描述：
 * 实现RFC6479标准的重放检测算法，使用滑动窗口和位图机制来高效
 * 检测和防止数据包重放攻击。避免使用位移操作以提升性能。
 * 
 * RFC6479重放检测原理：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    滑动窗口重放检测                          │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  滑动窗口结构：                                             │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │             重放检测窗口                             │   │
 * │  │  (COUNTER_WINDOW_SIZE 个序列号范围)                  │   │
 * │  │                                                     │   │
 * │  │  旧包区域    │    滑动窗口    │   新包区域            │   │
 * │  │   (拒绝)     │   (检查位图)   │   (直接接受)          │   │
 * │  │              │               │                      │   │
 * │  │ ──X──X──X──  │ ─✓─ ─?─ ─✓─  │  ─?─ ─?─ ─?─        │   │
 * │  │              │               │                      │   │
 * │  └──────────────┼───────────────┼──────────────────────┘   │
 * │                 │               │                          │
 * │            当前窗口起始      当前最大                       │
 * │            counter-window   counter                        │
 * │                                                             │
 * │  处理逻辑：                                                 │
 * │  • 如果 their_counter > counter：接受，更新窗口             │
 * │  • 如果在窗口内且未接收过：接受，设置位图                   │
 * │  • 如果在窗口内但已接收过：拒绝 (重放)                      │
 * │  • 如果 their_counter < counter-window：拒绝 (太老)         │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 位图索引计算：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                      位图索引算法                            │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  位图数组结构：                                             │
 * │  backtrack[0]  backtrack[1]  backtrack[2]  ...             │
 * │  │63...0│       │63...0│       │63...0│                   │
 * │                                                             │
 * │  索引计算：                                                 │
 * │  array_index = their_counter >> ilog2(BITS_PER_LONG)       │
 * │              = their_counter / BITS_PER_LONG               │
 * │                                                             │
 * │  bit_index = their_counter & (BITS_PER_LONG - 1)           │
 * │            = their_counter % BITS_PER_LONG                 │
 * │                                                             │
 * │  环形数组索引：                                             │
 * │  final_index = array_index & (TOTAL_ARRAYS - 1)            │
 * │                                                             │
 * │  示例 (BITS_PER_LONG=64)：                                  │
 * │  their_counter=130 → array_index=2, bit_index=2            │
 * │  their_counter=200 → array_index=3, bit_index=8            │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 窗口更新算法：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    窗口清理和更新                            │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  当接收到新的最大序列号时：                                  │
 * │                                                             │
 * │  1. 计算需要清理的数组范围                                   │
 * │     old_index = old_counter >> ilog2(BITS_PER_LONG)        │
 * │     new_index = new_counter >> ilog2(BITS_PER_LONG)        │
 * │     clear_count = min(new_index - old_index, MAX_ARRAYS)    │
 * │                                                             │
 * │  2. 循环清理过期的位图数组                                   │
 * │     for (i = 1; i <= clear_count; i++)                     │
 * │         backtrack[(old_index + i) % MAX_ARRAYS] = 0         │
 * │                                                             │
 * │  3. 更新当前最大计数器                                       │
 * │     counter = their_counter                                 │
 * │                                                             │
 * │  优势：                                                     │
 * │  • 避免逐位清理，提高性能                                   │
 * │  • 保持O(1)的平均复杂度                                     │
 * │  • 自动处理序列号回绕                                       │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 安全特性：
 * 1. 防重放攻击 - 滑动窗口机制拒绝旧包
 * 2. 防DoS攻击 - 限制最大序列号范围
 * 3. 内存安全 - 固定大小位图，无动态分配
 * 4. 并发安全 - 自旋锁保护关键区域
 * 
 * 性能优化：
 * 1. 避免位移操作 - 使用除法和取模
 * 2. 批量清理 - 按数组清理而非按位清理
 * 3. 环形缓冲区 - 复用位图空间
 * 4. 原子位操作 - test_and_set_bit()
 */
/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static bool counter_validate(struct noise_replay_counter *counter, u64 their_counter)
{
	unsigned long index, index_current, top, i;
	bool ret = false;

	/* 获取自旋锁，保护重放计数器的并发访问 */
	spin_lock_bh(&counter->lock);

	/* 第一层安全检查：序列号范围限制 */
	/* 防止序列号过大导致的DoS攻击和整数溢出 */
	if (unlikely(counter->counter >= REJECT_AFTER_MESSAGES + 1 ||    /* 本地计数器超限 */
		     their_counter >= REJECT_AFTER_MESSAGES))              /* 对方计数器超限 */
		goto out;

	/* RFC6479要求：序列号从1开始，0保留作为特殊用途 */
	++their_counter;

	/* 第二层安全检查：滑动窗口范围检查 */
	/* 如果包太旧（在窗口外），直接拒绝 */
	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) <             /* 窗口左边界检查 */
		     counter->counter))                                    /* their_counter + 窗口大小 < 当前计数器 */
		goto out;

	/* 计算对方序列号在位图中的数组索引 */
	index = their_counter >> ilog2(BITS_PER_LONG);                  /* 等价于 their_counter / BITS_PER_LONG */

	/* 情况1：接收到新的最大序列号，需要更新窗口 */
	if (likely(their_counter > counter->counter)) {
		/* 计算当前计数器的数组索引 */
		index_current = counter->counter >> ilog2(BITS_PER_LONG);
		
		/* 计算需要清理的数组数量，避免清理过多 */
		top = min_t(unsigned long, index - index_current,
			    COUNTER_BITS_TOTAL / BITS_PER_LONG);
			    
		/* 批量清理过期的位图数组，提高性能 */
		for (i = 1; i <= top; ++i)
			counter->backtrack[(i + index_current) &           /* 环形索引计算 */
				((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
				
		/* 更新最大序列号计数器 */
		counter->counter = their_counter;
	}

	/* 计算最终的环形数组索引 */
	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;             /* 等价于 index % ARRAY_COUNT */
	
	/* 原子检查并设置位图位：如果未设置过则设置并返回true，否则返回false */
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1),   /* 位索引 = their_counter % BITS_PER_LONG */
				&counter->backtrack[index]);               /* 目标位图数组 */

out:
	/* 释放自旋锁 */
	spin_unlock_bh(&counter->lock);
	return ret;                                                    /* 返回验证结果 */
}

#include "selftest/counter.c"

static void wg_packet_consume_data_done(struct wg_peer *peer,
					struct sk_buff *skb,
					struct endpoint *endpoint)
{
	struct net_device *dev = peer->device->dev;
	unsigned int len, len_before_trim;
	struct wg_peer *routed_peer;

	wg_socket_set_peer_endpoint(peer, endpoint);

	if (unlikely(wg_noise_received_with_keypair(&peer->keypairs,
						    PACKET_CB(skb)->keypair))) {
		wg_timers_handshake_complete(peer);
		wg_packet_send_staged_packets(peer);
	}

	keep_key_fresh(peer);

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		update_rx_stats(peer, message_data_len(0));
		net_dbg_ratelimited("%s: Receiving keepalive packet from peer %llu (%pISpfsc)\n",
				    dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		goto packet_processed;
	}

	wg_timers_data_received(peer);

	if (unlikely(skb_network_header(skb) < skb->head))
		goto dishonest_packet_size;
	if (unlikely(!(pskb_network_may_pull(skb, sizeof(struct iphdr)) &&
		       (ip_hdr(skb)->version == 4 ||
			(ip_hdr(skb)->version == 6 &&
			 pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))))))
		goto dishonest_packet_type;

	skb->dev = dev;
	/* We've already verified the Poly1305 auth tag, which means this packet
	 * was not modified in transit. We can therefore tell the networking
	 * stack that all checksums of every layer of encapsulation have already
	 * been checked "by the hardware" and therefore is unnecessary to check
	 * again in software.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifndef COMPAT_CANNOT_USE_CSUM_LEVEL
	skb->csum_level = ~0; /* All levels */
#endif
	skb->protocol = ip_tunnel_parse_protocol(skb);
	if (skb->protocol == htons(ETH_P_IP)) {
		len = ntohs(ip_hdr(skb)->tot_len);
		if (unlikely(len < sizeof(struct iphdr)))
			goto dishonest_packet_size;
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ip_hdr(skb)->tos);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		len = ntohs(ipv6_hdr(skb)->payload_len) +
		      sizeof(struct ipv6hdr);
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ipv6_get_dsfield(ipv6_hdr(skb)));
	} else {
		goto dishonest_packet_type;
	}

	if (unlikely(len > skb->len))
		goto dishonest_packet_size;
	len_before_trim = skb->len;
	if (unlikely(pskb_trim(skb, len)))
		goto packet_processed;

	routed_peer = wg_allowedips_lookup_src(&peer->device->peer_allowedips,
					       skb);
	wg_peer_put(routed_peer); /* We don't need the extra reference. */

	if (unlikely(routed_peer != peer))
		goto dishonest_packet_peer;

	napi_gro_receive(&peer->napi, skb);
	update_rx_stats(peer, message_data_len(len_before_trim));
	return;

dishonest_packet_peer:
	net_dbg_skb_ratelimited("%s: Packet has unallowed src IP (%pISc) from peer %llu (%pISpfsc)\n",
				dev->name, skb, peer->internal_id,
				&peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_type:
	net_dbg_ratelimited("%s: Packet is neither ipv4 nor ipv6 from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_size:
	net_dbg_ratelimited("%s: Packet has incorrect size from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_length_errors;
	goto packet_processed;
packet_processed:
	dev_kfree_skb(skb);
}

int wg_packet_rx_poll(struct napi_struct *napi, int budget)
{
	struct wg_peer *peer = container_of(napi, struct wg_peer, napi);
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	enum packet_state state;
	struct sk_buff *skb;
	int work_done = 0;
	bool free;

	if (unlikely(budget <= 0))
		return 0;

	while ((skb = wg_prev_queue_peek(&peer->rx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(skb)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		wg_prev_queue_drop_peeked(&peer->rx_queue);
		keypair = PACKET_CB(skb)->keypair;
		free = true;

		if (unlikely(state != PACKET_STATE_CRYPTED))
			goto next;

		if (unlikely(!counter_validate(&keypair->receiving_counter,
					       PACKET_CB(skb)->nonce))) {
			net_dbg_ratelimited("%s: Packet has invalid nonce %llu (max %llu)\n",
					    peer->device->dev->name,
					    PACKET_CB(skb)->nonce,
					    keypair->receiving_counter.counter);
			goto next;
		}

		if (unlikely(wg_socket_endpoint_from_skb(&endpoint, skb)))
			goto next;

		wg_reset_packet(skb, false);
		wg_packet_consume_data_done(peer, skb, &endpoint);
		free = false;

next:
		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		if (unlikely(free))
			dev_kfree_skb(skb);

		if (++work_done >= budget)
			break;
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	return work_done;
}

void wg_packet_decrypt_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	simd_context_t simd_context;
	struct sk_buff *skb;

	simd_get(&simd_context);
	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state =
			likely(decrypt_packet(skb, PACKET_CB(skb)->keypair,
					      &simd_context)) ?
				PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
		wg_queue_enqueue_per_peer_rx(skb, state);
		simd_relax(&simd_context);
	}

	simd_put(&simd_context);
}

static void wg_packet_consume_data(struct wg_device *wg, struct sk_buff *skb)
{
	__le32 idx = ((struct message_data *)skb->data)->key_idx;
	struct wg_peer *peer = NULL;
	int ret;

	rcu_read_lock_bh();
	PACKET_CB(skb)->keypair =
		(struct noise_keypair *)wg_index_hashtable_lookup(
			wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx,
			&peer);
	if (unlikely(!wg_noise_keypair_get(PACKET_CB(skb)->keypair)))
		goto err_keypair;

	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	ret = wg_queue_enqueue_per_device_and_peer(&wg->decrypt_queue, &peer->rx_queue, skb,
						   wg->packet_crypt_wq, &wg->decrypt_queue.last_cpu);
	if (unlikely(ret == -EPIPE))
		wg_queue_enqueue_per_peer_rx(skb, PACKET_STATE_DEAD);
	if (likely(!ret || ret == -EPIPE)) {
		rcu_read_unlock_bh();
		return;
	}
err:
	wg_noise_keypair_put(PACKET_CB(skb)->keypair, false);
err_keypair:
	rcu_read_unlock_bh();
	wg_peer_put(peer);
	dev_kfree_skb(skb);
}

/*
 * ===================================================================
 * 主要数据包接收入口点
 * ===================================================================
 */

/**
 * wg_packet_receive - WireGuard数据包接收处理主入口函数
 * @wg: WireGuard设备结构指针
 * @skb: 接收到的网络数据包
 * 
 * 功能描述：
 * 这是WireGuard接收处理的核心入口点，负责对所有进入的UDP包进行
 * 分类、验证和分发处理。实现了高效的多核负载均衡和拥塞控制。
 * 
 * 整体处理架构：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                WireGuard包接收处理流程                       │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  ┌─────────────┐                                           │
 * │  │ 网络包进入   │ ← 来自UDP套接字层                         │
 * │  └─────────────┘                                           │
 * │         │                                                  │
 * │         ▼                                                  │
 * │  ┌─────────────────────────────────────┐                  │
 * │  │        包头预处理验证                │                  │
 * │  │   prepare_skb_header()              │                  │
 * │  │ • UDP头部验证                       │                  │
 * │  │ • WireGuard消息头检查               │                  │
 * │  │ • 内存布局调整                      │                  │
 * │  └─────────────────────────────────────┘                  │
 * │         │                                                  │
 * │         ▼                                                  │
 * │  ┌─────────────────────────────────────┐                  │
 * │  │        消息类型识别                 │                  │
 * │  │   SKB_TYPE_LE32()                   │                  │
 * │  └─────────────────────────────────────┘                  │
 * │         │                                                  │
 * │    ┌────┼────┐                                            │
 * │    ▼         ▼                                            │
 * │ ┌───────┐  ┌─────────┐                                    │
 * │ │握手包 │  │ 数据包  │                                    │
 * │ └───────┘  └─────────┘                                    │
 * │    │           │                                          │
 * │    ▼           ▼                                          │
 * │ ┌────────┐  ┌─────────────┐                              │
 * │ │异步队列│  │  同步解密   │                              │
 * │ │处理    │  │  转发       │                              │
 * │ └────────┘  └─────────────┘                              │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 消息类型处理策略：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                   消息处理策略表                             │
 * ├─────────────────┬───────────────┬───────────────────────────┤
 * │   消息类型      │   处理方式    │        处理特点           │
 * ├─────────────────┼───────────────┼───────────────────────────┤
 * │ HANDSHAKE_INIT  │   异步队列    │ • CPU负载均衡             │
 * │ HANDSHAKE_RESP  │   处理        │ • 拥塞控制                │
 * │ HANDSHAKE_COOKIE│               │ • RNG状态检查             │
 * │                 │               │ • 多核并行处理            │
 * ├─────────────────┼───────────────┼───────────────────────────┤
 * │ MESSAGE_DATA    │   同步处理    │ • 立即解密                │
 * │                 │               │ • QoS信息保存             │
 * │                 │               │ • 快速转发                │
 * └─────────────────┴───────────────┴───────────────────────────┘
 * 
 * 拥塞控制机制：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     拥塞控制策略                             │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  队列长度阈值判断：                                         │
 * │                                                             │
 * │  if (队列长度 > MAX_QUEUED / 2) {                           │
 * │      使用非阻塞入队模式                                     │
 * │      spin_trylock_bh() - 尝试获取锁                         │
 * │      失败则直接丢包，避免阻塞                                │
 * │  } else {                                                   │
 * │      使用阻塞入队模式                                       │
 * │      ptr_ring_produce_bh() - 正常入队                       │
 * │      可能短暂阻塞等待队列空间                                │
 * │  }                                                          │
 * │                                                             │
 * │  优势：                                                     │
 * │  • 防止DoS攻击导致的队列溢出                                │
 * │  • 保持系统响应性能                                         │
 * │  • 优雅降级服务质量                                         │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 性能优化特性：
 * 1. 多核负载均衡 - 握手处理分布到不同CPU核心
 * 2. 异步处理握手 - 避免阻塞数据包处理
 * 3. 同步处理数据 - 最小化数据包延迟
 * 4. 智能拥塞控制 - 防止资源耗尽攻击
 * 5. QoS信息保留 - 支持服务质量传递
 * 
 * 安全防护：
 * 1. 随机数生成器状态检查 - 确保握手安全性
 * 2. 严格的包验证 - 多层次完整性检查
 * 3. 队列长度监控 - 防止内存耗尽
 * 4. 错误包丢弃 - 避免处理恶意包
 */
void wg_packet_receive(struct wg_device *wg, struct sk_buff *skb)
{
    /* 第一阶段：包头预处理和基本验证 */
    if (unlikely(prepare_skb_header(skb, wg) < 0))
        goto err;
        
    /* 第二阶段：根据WireGuard消息类型进行分发处理 */
    switch (SKB_TYPE_LE32(skb)) {
    
    /* 握手相关消息：需要异步队列处理 */
    case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):    /* 握手初始化请求 */
    case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):      /* 握手响应消息 */
    case cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE): {      /* 握手Cookie消息 */
        int cpu, ret = -EBUSY;

        /* 安全检查：确保随机数生成器已准备就绪 */
        /* 握手过程需要高质量随机数生成临时密钥 */
        if (unlikely(!rng_is_initialized()))
            goto drop;
            
        /* 拥塞控制：基于队列长度的自适应处理策略 */
        if (atomic_read(&wg->handshake_queue_len) > MAX_QUEUED_INCOMING_HANDSHAKES / 2) {
            /* 高负载模式：使用非阻塞入队，防止系统锁死 */
            if (spin_trylock_bh(&wg->handshake_queue.ring.producer_lock)) {
                ret = __ptr_ring_produce(&wg->handshake_queue.ring, skb);
                spin_unlock_bh(&wg->handshake_queue.ring.producer_lock);
            }
            /* 如果获取锁失败，ret保持-EBUSY，包将被丢弃 */
        } else {
            /* 正常负载模式：使用阻塞入队，确保包不丢失 */
            ret = ptr_ring_produce_bh(&wg->handshake_queue.ring, skb);
        }
            
        /* 入队失败处理：记录并丢弃包 */
        if (ret) {
    drop:
            net_dbg_skb_ratelimited("%s: Dropping handshake packet from %pISpfsc\n",
                        wg->dev->name, skb);
            goto err;
        }
        
        /* 更新队列统计计数器 */
        atomic_inc(&wg->handshake_queue_len);
        
        /* CPU负载均衡：选择下一个可用CPU核心 */
        cpu = wg_cpumask_next_online(&wg->handshake_queue.last_cpu);
        
        /* 异步握手处理：在选定CPU上调度工作队列 */
        /* 最终调用 wg_packet_handshake_receive_worker() */
		/* Queues up a call to packet_process_queued_handshake_packets(skb): */
        queue_work_on(cpu, wg->handshake_receive_wq,
                  &per_cpu_ptr(wg->handshake_queue.worker, cpu)->work);
        break;
    }
    
    /* 数据包：需要立即同步处理以最小化延迟 */
    case cpu_to_le32(MESSAGE_DATA):
        /* 保存QoS/DSCP字段信息，用于后续转发时的服务质量处理 */
        PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
        
        /* 立即进入解密和转发流程，保持低延迟特性 */
        wg_packet_consume_data(wg, skb);
        break;
        
    default:
        /* 未知消息类型：这应该不会发生，如果发生则是程序错误 */
        WARN(1, "Non-exhaustive parsing of packet header lead to unknown packet type!\n");
        goto err;
    }
    return;  /* 正常处理完成 */

err:
    /* 错误处理：释放skb内存，防止内存泄漏 */
    dev_kfree_skb(skb);
}
