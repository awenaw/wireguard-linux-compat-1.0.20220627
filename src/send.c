// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

// --aw 多核并行加密：在多个 CPU 核心上并行加密出站数据包，然后在单个核心上按顺序发送
// 工作队列管理：使用工作队列和环形缓冲区来管理并行处理
// 握手消息处理：发送协议握手和 cookie 消息

/*
 * WireGuard 数据包发送模块
 * 
 * 本文件实现了 WireGuard 协议中数据包的发送功能，包括：
 * 1. 握手包的创建和发送（握手初始化、响应、Cookie）
 * 2. 数据包的加密和传输
 * 3. 密钥管理和刷新
 * 4. Keepalive 包的发送
 * 5. 排队和工作队列管理
 */

/* WireGuard 内部头文件 */
#include "queueing.h"    /* 数据包队列管理 */
#include "timers.h"      /* 定时器功能 */
#include "device.h"      /* 设备管理 */
#include "peer.h"        /* 对等节点管理 */
#include "socket.h"      /* 套接字操作 */
#include "messages.h"    /* 消息格式定义 */
#include "cookie.h"      /* Cookie 认证 */

/* Linux 内核头文件 */
#include <linux/simd.h>        /* SIMD 指令支持 */
#include <linux/uio.h>         /* 用户空间 I/O */
#include <linux/inetdevice.h>  /* 网络设备接口 */
#include <linux/socket.h>      /* 套接字定义 */
#include <net/ip_tunnels.h>    /* IP 隧道支持 */
#include <net/udp.h>           /* UDP 协议 */
#include <net/sock.h>          /* 套接字结构 */

/*
 * 发送握手初始化包
 * 
 * 本函数负责创建并发送 WireGuard 握手协议的第一个消息（初始化消息）。
 * 这是启动握手过程的关键步骤，用于建立安全的加密通道。
 * 
 * @peer: 目标对等节点
 */
static void wg_packet_send_handshake_initiation(struct wg_peer *peer)
{
	struct message_handshake_initiation packet;

	/* 检查限速：避免频繁发送握手包 */
	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT))
		return; /* 该函数受到限速控制 */

	/* 更新最后发送握手的时间戳 */
	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	/* 创建握手初始化消息 */
	if (wg_noise_handshake_create_initiation(&packet, &peer->handshake)) {
		/* 添加 MAC 认证标签防止攻击 */
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		
		/* 更新定时器的相关状态 */
		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);
		
		/* 再次更新时间戳（确保精确性） */
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		
		/* 发送握手包，使用握手 DSCP 标记 */
		wg_socket_send_buffer_to_peer(peer, &packet, sizeof(packet),
					      HANDSHAKE_DSCP);
		
		/* 通知定时器系统握手已初始化 */
		wg_timers_handshake_initiated(peer);
	}
}

/*
 * 握手发送工作队列处理函数
 * 
 * 这是一个工作队列回调函数，用于在独立的工作线程中
 * 处理握手初始化的发送。这种异步处理方式避免了阻塞主线程。
 * 
 * @work: 工作队列项目
 */
void wg_packet_handshake_send_worker(struct work_struct *work)
{
	/* 从工作项目中获取对等节点结构 */
	struct wg_peer *peer = container_of(work, struct wg_peer,
					    transmit_handshake_work);

	/* 执行握手初始化发送 */
	wg_packet_send_handshake_initiation(peer);
	
	/* 释放对等节点引用计数 */
	wg_peer_put(peer);
}

/*
 * 将握手初始化任务加入队列
 * 
 * 该函数将握手初始化任务添加到工作队列中进行异步处理。
 * 它会执行必要的检查以避免不必要的队列操作。
 * 
 * @peer: 目标对等节点
 * @is_retry: 是否为重试操作
 */
void wg_packet_send_queued_handshake_initiation(struct wg_peer *peer,
						bool is_retry)
{
	/* 如果不是重试，重置握手尝试计数器 */
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	/* 进入 RCU 读取临界区，关闭下半部 */
	rcu_read_lock_bh();
	
	/* 在这里检查 last_sent_handshake，除了在实际函数中检查外，
	 * 这样做是为了避免在不严格必要的情况下进行队列操作。
	 */
	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT) ||
			unlikely(READ_ONCE(peer->is_dead)))
		goto out;

	/* 增加对等节点引用计数 */
	wg_peer_get(peer);
	
	/* 将握手发送任务加入工作队列。
	 * 在 packet_send_queued_handshakes(peer) 中会调用 peer_put(peer)。
	 */
	if (!queue_work(peer->device->handshake_send_wq,
			&peer->transmit_handshake_work))
		/* 如果工作已经在队列中，我们需要释放额外的引用 */
		wg_peer_put(peer);
out:
	/* 退出 RCU 读取临界区 */
	rcu_read_unlock_bh();
}

/*
 * 发送握手响应包
 * 
 * 本函数负责发送 WireGuard 握手协议的第二个消息（响应消息）。
 * 在收到初始化消息后，服务端使用此函数回复并建立会话。
 * 
 * @peer: 目标对等节点
 */
void wg_packet_send_handshake_response(struct wg_peer *peer)
{
	struct message_handshake_response packet;

	/* 更新最后发送握手的时间戳 */
	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	/* 创建握手响应消息 */
	if (wg_noise_handshake_create_response(&packet, &peer->handshake)) {
		/* 添加 MAC 认证标签 */
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		
		/* 尝试开始新的会话 */
		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			/* 通知定时器系统会话已建立 */
			wg_timers_session_derived(peer);
			wg_timers_any_authenticated_packet_traversal(peer);
			wg_timers_any_authenticated_packet_sent(peer);
			
			/* 再次更新时间戳 */
			atomic64_set(&peer->last_sent_handshake,
				     ktime_get_coarse_boottime_ns());
			
			/* 发送响应包 */
			wg_socket_send_buffer_to_peer(peer, &packet,
						      sizeof(packet),
						      HANDSHAKE_DSCP);
		}
	}
}

/*
 * 发送握手 Cookie 包
 * 
 * 当握手请求被拒绝时（通常由于频繁请求或安全策略），
 * 发送一个 Cookie 包来帮助客户端通过 Cookie 验证。
 * 
 * @wg: WireGuard 设备
 * @initiating_skb: 触发该响应的初始数据包
 * @sender_index: 发送者索引
 */
void wg_packet_send_handshake_cookie(struct wg_device *wg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index)
{
	struct message_handshake_cookie packet;

	/* 记录调试信息 */
	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n",
				wg->dev->name, initiating_skb);
	
	/* 创建 Cookie 消息 */
	wg_cookie_message_create(&packet, initiating_skb, sender_index,
				 &wg->cookie_checker);
	
	/* 作为对原始数据包的回复发送 Cookie 包 */
	wg_socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet,
					      sizeof(packet));
}

/*
 * 保持密钥的新鲜度
 * 
 * 这个函数检查当前密钥的状态，并在需要时启动密钥更新过程。
 * 密钥需要更新的情况包括：
 * 1. 发送数据包数量超过了限制 (REKEY_AFTER_MESSAGES)
 * 2. 密钥使用时间超过了限制 (REKEY_AFTER_TIME)
 * 
 * @peer: 要检查的对等节点
 */
static void keep_key_fresh(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	bool send;

	/* 进入 RCU 读取临界区获取密钥对 */
	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	
	/* 检查是否需要重新生成密钥：
	 * 1. 密钥对存在且发送密钥有效
	 * 2. 发送计数器超过限制，或者
	 * 3. 我是初始化者且密钥已过期
	 */
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       (atomic64_read(&keypair->sending_counter) > REKEY_AFTER_MESSAGES ||
		(keypair->i_am_the_initiator &&
		 wg_birthdate_has_expired(keypair->sending.birthdate, REKEY_AFTER_TIME)));
	rcu_read_unlock_bh();

	/* 如果需要，发送新的握手初始化以更新密钥 */
	if (unlikely(send))
		wg_packet_send_queued_handshake_initiation(peer, false);
}

/*
 * 计算数据包所需的填充大小
 * 
 * 为了掩盖真实数据包的大小，增强隐私性，需要对数据包进行填充。
 * 填充将数据包的大小对齐到 MESSAGE_PADDING_MULTIPLE 的倍数。
 * 同时需要考虑 MTU 限制以避免数据包过大。
 * 
 * @skb: 要计算填充的数据包
 * @return: 需要添加的填充字节数
 */
static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	unsigned int padded_size, last_unit = skb->len;

	/* 如果没有设置 MTU，简单对齐到填充倍数 */
	if (unlikely(!PACKET_CB(skb)->mtu))
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit;

	/* 对 MTU 进行模运算，以防网络层给我们一个比 MTU 更大的数据包。
	 * 在这种情况下，我们不希望最终的减法在 padded_size 被限制时发生溢出。
	 * 幸运的是，这种情况非常罕见，所以我们针对不发生这种情况进行优化。
	 */
	if (unlikely(last_unit > PACKET_CB(skb)->mtu))
		last_unit %= PACKET_CB(skb)->mtu;

	/* 计算填充后的大小，但不超过 MTU */
	padded_size = min(PACKET_CB(skb)->mtu,
			  ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE));
	
	/* 返回需要添加的填充字节数 */
	return padded_size - last_unit;
}

/*
 * 加密数据包
 * 
 * 这个函数将一个明文数据包加密为 WireGuard 数据消息。
 * 它处理所有必要的步骤：填充、校验和、添加头部和加密。
 * 
 * @skb: 要加密的数据包
 * @keypair: 用于加密的密钥对
 * @simd_context: SIMD 上下文，用于优化加密性能
 * @return: 成功返回 true，失败返回 false
 */
static bool encrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair,
			   simd_context_t *simd_context)
{
	unsigned int padding_len, plaintext_len, trailer_len;
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct message_data *header;
	struct sk_buff *trailer;
	int num_frags;

	/* 在加密前强制计算哈希值，保证流分析在内部数据包上保持一致 */
	skb_get_hash(skb);

	/* 计算各种长度 */
	padding_len = calculate_skb_padding(skb);    /* 填充长度 */
	trailer_len = padding_len + noise_encrypted_len(0);  /* 尾部长度（填充 + 认证标签） */
	plaintext_len = skb->len + padding_len;      /* 明文总长度 */

	/* 扩展数据部分以为填充和认证标签腾出空间 */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* 将填充部分设置为零，并确保它和认证标签都是 skb 的一部分 */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* 扩展头部部分以为我们的头部和网络协议栈的头部腾出空间 */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* 如果需要，完成内部数据包的校验和计算 */
	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb)))
		return false;

	/* 只有在校验和计算完成后，我们才能安全地在末尾添加填充和头部 */
	skb_set_inner_network_header(skb, 0);
	header = (struct message_data *)skb_push(skb, sizeof(*header));
	header->header.type = cpu_to_le32(MESSAGE_DATA);  /* 消息类型 */
	header->key_idx = keypair->remote_index;          /* 密钥索引 */
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce); /* 计数器/nonce */
	pskb_put(skb, trailer, trailer_len);

	/* 现在我们可以加密分散聚集段 */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data),
			 noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	
	/* 使用 ChaCha20Poly1305 算法就地加密 */
	return chacha20poly1305_encrypt_sg_inplace(sg, plaintext_len, NULL, 0,
						   PACKET_CB(skb)->nonce,
						   keypair->sending.key,
						   simd_context);
}

/*
 * 发送 Keepalive 包
 * 
 * Keepalive 包用于维持连接活性，特别是在 NAT 环境中保持端口映射。
 * 它们是空的数据包（只有 WireGuard 头部，无有载荷）。
 * 
 * @peer: 目标对等节点
 */
void wg_packet_send_keepalive(struct wg_peer *peer)
{
	struct sk_buff *skb;

	/* 如果暂存队列为空，创建一个 keepalive 包 */
	if (skb_queue_empty(&peer->staged_packet_queue)) {
		/* 分配最小大小的数据包缓冲区 */
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH,
				GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		
		/* 为头部预留空间 */
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		PACKET_CB(skb)->mtu = skb->dev->mtu;
		
		/* 将 keepalive 包加入暂存队列 */
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	/* 发送暂存队列中的所有包（包括新创建的 keepalive 包） */
	wg_packet_send_staged_packets(peer);
}

/*
 * 完成数据包的发送处理
 * 
 * 这个函数在数据包加密完成后被调用，负责实际的网络发送
 * 和相关的后续处理（定时器更新、密钥管理等）。
 * 
 * @peer: 目标对等节点
 * @first: 要发送的数据包列表的第一个包
 */
static void wg_packet_create_data_done(struct wg_peer *peer, struct sk_buff *first)
{
	struct sk_buff *skb, *next;
	bool is_keepalive, data_sent = false;

	/* 阶段 1：更新定时器状态：有认证数据包通过和发送 */
// 	  作用：
//   - 通知定时器系统有已认证的数据包通过
//   - 更新最后一次发送数据包的时间戳
//   - 用于触发相关的超时管理（如连接保活、重新握手等）
	wg_timers_any_authenticated_packet_traversal(peer);
	wg_timers_any_authenticated_packet_sent(peer);
	
	/* 遍历数据包列表，逐个发送 */
	skb_list_walk_safe(first, skb, next) {
		/* 检查是否为 keepalive 包（只有头部，无数据） */
		is_keepalive = skb->len == message_data_len(0);
		
		/* 发送数据包到对等节点 */
		// aw:准备走内核发送到对端了
		if (likely(!wg_socket_send_skb_to_peer(peer, skb,
				PACKET_CB(skb)->ds) && !is_keepalive))
			data_sent = true;  /* 记录成功发送了非-keepalive 数据 */
	}

	/* 如果发送了真实数据，更新数据发送定时器 */
	if (likely(data_sent))
		wg_timers_data_sent(peer);

	/* 检查并维护密钥的新鲜度 */
	keep_key_fresh(peer);
}

/*
 * 数据包发送工作队列处理函数
 * 
 * 这个函数在独立的工作线程中处理已加密的数据包的发送。
 * 它从发送队列中取出包并将它们发送给对等节点。
 * 
 * @work: 工作队列项目
 */
void wg_packet_tx_worker(struct work_struct *work)
{
	/* 从工作项目中获取对等节点结构 */
	struct wg_peer *peer = container_of(work, struct wg_peer, transmit_packet_work);
	struct noise_keypair *keypair;
	enum packet_state state;
	struct sk_buff *first;

	/* 循环处理队列中的数据包 */
	while ((first = wg_prev_queue_peek(&peer->tx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(first)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		
		/* 从队列中移除已处理的包 */
		wg_prev_queue_drop_peeked(&peer->tx_queue);
		keypair = PACKET_CB(first)->keypair;

		/* 根据数据包状态进行处理 */
		if (likely(state == PACKET_STATE_CRYPTED)) {
			/* 包已成功加密，发送它 */
			wg_packet_create_data_done(peer, first);
		} else {
			/* 包加密失败或处于无效状态，释放它 */
			kfree_skb_list(first);
		}

		/* 清理资源 */
		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		
		/* 如果需要调度，主动让出 CPU */
		if (need_resched())
			cond_resched();
	}
}

/*
 * 数据包加密工作队列处理函数
 * 
 * 这个函数在独立的工作线程中处理数据包的加密操作。
 * 它从加密队列中取出包，对它们进行加密，然后将结果放入发送队列。
 * 
 * @work: 工作队列项目
 */
void wg_packet_encrypt_worker(struct work_struct *work)
{
	/* 从多核工作者中获取加密队列 */
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	struct sk_buff *first, *skb, *next;
	simd_context_t simd_context;

	/* 获取 SIMD 上下文以优化加密性能 */
	simd_get(&simd_context);
	
	/* 循环处理队列中的数据包 */
	while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state = PACKET_STATE_CRYPTED;

		/* 遍历包列表，逐个加密 */
		skb_list_walk_safe(first, skb, next) {
			if (likely(encrypt_packet(skb,
						  PACKET_CB(first)->keypair,
						  &simd_context))) {
				/* 加密成功，重置包的状态 */
				wg_reset_packet(skb, true);
			} else {
				/* 加密失败，标记为死亡状态 */
				state = PACKET_STATE_DEAD;
				break;
			}
		}
		
		/* 将加密后的包放入发送队列 */
		wg_queue_enqueue_per_peer_tx(first, state);

		/* 放松 SIMD 上下文，允许其他任务运行 */
		simd_relax(&simd_context);
	}
	
	/* 释放 SIMD 上下文 */
	simd_put(&simd_context);
}

/*
 * 创建数据包并加入加密队列
 * 
 * 这个函数将数据包加入加密队列进行异步处理。
 * 它会检查对等节点的状态并将包分配给适当的加密工作者。
 * 
 * @peer: 目标对等节点
 * @first: 要处理的数据包列表的第一个包
 */
static void wg_packet_create_data(struct wg_peer *peer, struct sk_buff *first)
{
	struct wg_device *wg = peer->device;
	int ret = -EINVAL;

	/* 进入 RCU 读取临界区 */
	rcu_read_lock_bh();
	
	/* 检查对等节点是否已死亡 */
	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	/* 将数据包加入设备和对等节点的加密队列 */
	ret = wg_queue_enqueue_per_device_and_peer(&wg->encrypt_queue, &peer->tx_queue, first,
						   wg->packet_crypt_wq, &wg->encrypt_queue.last_cpu);
	
	/* 如果队列已满或关闭，标记包为死亡状态 */
	if (unlikely(ret == -EPIPE))
		wg_queue_enqueue_per_peer_tx(first, PACKET_STATE_DEAD);
err:
	/* 退出 RCU 读取临界区 */
	rcu_read_unlock_bh();
	
	/* 如果成功或者已处理错误，直接返回 */
	if (likely(!ret || ret == -EPIPE))
		return;
	
	/* 在失败情况下清理资源 */
	wg_noise_keypair_put(PACKET_CB(first)->keypair, false);
	wg_peer_put(peer);
	kfree_skb_list(first);
}

/*
 * 清空暂存数据包队列
 * 
 * 这个函数用于在对等节点断开连接或其他特殊情况下
 * 清空所有等待发送的数据包，并更新统计信息。
 * 
 * @peer: 要清空数据包的对等节点
 */
void wg_packet_purge_staged_packets(struct wg_peer *peer)
{
	/* 获取暂存队列的锁 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	
	/* 更新丢弃数据包的统计信息 */
	peer->device->dev->stats.tx_dropped += peer->staged_packet_queue.qlen;
	
	/* 清空整个队列 */
	__skb_queue_purge(&peer->staged_packet_queue);
	
	/* 释放锁 */
	spin_unlock_bh(&peer->staged_packet_queue.lock);
}

/*
 * 发送暂存的数据包
 * 
 * 这个函数将暂存队列中的所有数据包取出，为它们分配 nonce，
 * 然后将它们提交到加密和发送系统。如果密钥不可用，则将数据包
 * 放回队列并启动新的握手过程。
 * 
 * @peer: 目标对等节点
 */
void wg_packet_send_staged_packets(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	struct sk_buff_head packets;
	struct sk_buff *skb;

	/* 将当前暂存队列“偷”到我们的本地队列中 */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	
	/* 如果没有数据包需要发送，直接返回 */
	if (unlikely(skb_queue_empty(&packets)))
		return;

	/* 首先确保我们有一个有效密钥的有效引用 */
	rcu_read_lock_bh();
	keypair = wg_noise_keypair_get(
		rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	
	/* 检查密钥对是否存在 */
	if (unlikely(!keypair))
		goto out_nokey;
	
	/* 检查发送密钥是否有效 */
	if (unlikely(!READ_ONCE(keypair->sending.is_valid)))
		goto out_nokey;
	
	/* 检查密钥是否已过期 */
	if (unlikely(wg_birthdate_has_expired(keypair->sending.birthdate,
					      REJECT_AFTER_TIME)))
		goto out_invalid;

	/* 在确认有一个相对有效的密钥后，我们现在尝试为队列中的
	 * 所有数据包分配 nonce。如果不能为所有数据包分配 nonce，
	 * 我们就认为这是失败并等待下一次握手。
	 */
	skb_queue_walk(&packets, skb) {
		/* 外层 TOS 使用 0：防止信息泄露。
		 * TODO: 在未来的某个时点，我们可能会考虑使用 flowi->tos 作为外层。
		 */
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		
		/* 为每个数据包分配一个唯一的 nonce */
		PACKET_CB(skb)->nonce =
				atomic64_inc_return(&keypair->sending_counter) - 1;
		
		/* 检查 nonce 是否超过了安全限制 */
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	/* 断开链表连接，准备提交给加密系统 */
	packets.prev->next = NULL;
	wg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	
	/* 将数据包提交给加密和发送系统 */
	wg_packet_create_data(peer, packets.next);
	return;

out_invalid:
	/* 密钥已过期或无效，标记为无效 */
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	/* 没有可用的密钥，释放密钥对引用 */
	wg_noise_keypair_put(keypair, false);

	/* 如果我们在等待握手，就将数据包“孤儿化”，
	 * 这样它们就不会阻塞套接字的缓冲池。
	 */
	skb_queue_walk(&packets, skb)
		skb_orphan(skb);
	
	/* 然后将它们放回队列的顶部。如果数据包被快速添加，
	 * 我们不太担心意外地让事情有点乱序，因为这个队列是在
	 * 数据包能够被发送之前的，而且它也很小。
	 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* 如果我们因为密钥有问题而退出，这意味着我们应该启动一个新的握手。 */
	wg_packet_send_queued_handshake_initiation(peer, false);
}
