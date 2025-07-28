// SPDX-License-Identifier: GPL-2.0
/*
 * WireGuard Peer对象管理模块 - VPN连接中每个对等节点的生命周期管理
 * 核心功能：创建/销毁peer、引用计数、内存安全、RCU保护
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "peerlookup.h"
#include "noise.h"

#include <linux/kref.h>      // 引用计数管理
#include <linux/lockdep.h>   // 锁依赖检查，调试用
#include <linux/rcupdate.h>  // RCU读-拷贝-更新机制
#include <linux/list.h>      // 链表操作

// 全局peer对象内存缓存池，提升分配/释放性能
static struct kmem_cache *peer_cache;
// 全局peer计数器，为每个peer分配唯一ID，原子操作保证线程安全
static atomic64_t peer_counter = ATOMIC64_INIT(0);

/**
 * wg_peer_create - 创建新的WireGuard对等节点
 * @wg: 所属的WireGuard设备
 * @public_key: 对等节点的Curve25519公钥（32字节）
 * @preshared_key: 预共享密钥（32字节，可选加强安全）
 * 返回：成功返回peer指针，失败返回ERR_PTR
 */
struct wg_peer *wg_peer_create(struct wg_device *wg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct wg_peer *peer;
	int ret = -ENOMEM;  // 默认错误码：内存不足

	// 断言：必须持有设备更新锁，确保创建过程的线程安全
	lockdep_assert_held(&wg->device_update_lock);

	// 检查peer数量限制，防止资源耗尽攻击
	if (wg->num_peers >= MAX_PEERS_PER_DEVICE)
		return ERR_PTR(ret);

	// 从内存池分配peer对象，零初始化所有字段
	peer = kmem_cache_zalloc(peer_cache, GFP_KERNEL);
	if (unlikely(!peer))  // 内存分配失败
		return ERR_PTR(ret);
	// 初始化endpoint缓存，用于优化路由查找性能
	if (unlikely(dst_cache_init(&peer->endpoint_cache, GFP_KERNEL)))
		goto err;  // 初始化失败，跳转到错误处理

	// === 核心初始化过程 ===
	peer->device = wg;  // 关联到WireGuard设备
	// 初始化Noise协议握手状态，这是加密通信的核心
	wg_noise_handshake_init(&peer->handshake, &wg->static_identity,
				public_key, preshared_key, peer);
	// 分配全局唯一的内部ID，用于调试和日志追踪
	peer->internal_id = atomic64_inc_return(&peer_counter);
	// 初始化工作队列CPU绑定（nr_cpumask_bits表示未绑定到特定CPU）
	peer->serial_work_cpu = nr_cpumask_bits;
	// 初始化DDoS防护cookie机制
	wg_cookie_init(&peer->latest_cookie);
	// 初始化各种定时器（握手超时、保活、重传等）
	wg_timers_init(peer);
	// 预计算cookie验证需要的密钥材料，提升运行时性能
	wg_cookie_checker_precompute_peer_keys(peer);
	// 初始化密钥对更新的自旋锁，保护密钥轮换过程
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	// === 工作队列初始化 ===
	// 握手发送工作队列 - 异步处理握手包发送
	INIT_WORK(&peer->transmit_handshake_work, wg_packet_handshake_send_worker);
	// 数据包发送工作队列 - 异步处理数据包发送
	INIT_WORK(&peer->transmit_packet_work, wg_packet_tx_worker);
	// === 数据包队列初始化 ===
	wg_prev_queue_init(&peer->tx_queue);  // 发送队列
	wg_prev_queue_init(&peer->rx_queue);  // 接收队列
	// 初始化endpoint访问的读写锁，允许并发读取
	rwlock_init(&peer->endpoint_lock);
	// === 引用计数和生命周期管理 ===
	kref_init(&peer->refcount);  // 初始化引用计数为1
	// 暂存数据包队列（用于握手期间缓存数据包）
	skb_queue_head_init(&peer->staged_packet_queue);
	// 重置上次发送握手的时间戳
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	// === NAPI机制初始化（高性能网络中断处理） ===
	set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	// 注册NAPI处理函数，用于高效批量处理接收数据包
	netif_napi_add(wg->dev, &peer->napi, wg_packet_rx_poll,
		       NAPI_POLL_WEIGHT);
	napi_enable(&peer->napi);  // 启用NAPI处理
	// === 注册到各种查找数据结构 ===
	list_add_tail(&peer->peer_list, &wg->peer_list);  // 加入设备的peer链表
	INIT_LIST_HEAD(&peer->allowedips_list);  // 初始化允许IP地址列表
	wg_pubkey_hashtable_add(wg->peer_hashtable, peer);  // 加入公钥哈希表，支持快速查找
	++wg->num_peers;  // 增加设备的peer计数
	// 调试日志：记录peer创建成功
	pr_debug("%s: Peer %llu created\n", wg->dev->name, peer->internal_id);
	return peer;

err:
	// 错误处理：释放已分配的内存
	kmem_cache_free(peer_cache, peer);
	return ERR_PTR(ret);
}

/**
 * wg_peer_get_maybe_zero - 安全地获取peer引用
 * @peer: 要获取引用的peer对象
 * 使用RCU保护，只有在引用计数大于0时才增加引用，避免use-after-free
 * 返回：成功返回peer，失败返回NULL
 */
struct wg_peer *wg_peer_get_maybe_zero(struct wg_peer *peer)
{
	// RCU锁依赖检查：确保调用者持有RCU读锁，这是线程安全的前提
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
	// 原子操作：只有引用计数>0时才增加引用，避免访问已释放的对象
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

/**
 * peer_make_dead - 标记peer为"死亡"状态
 * @peer: 要标记的peer对象
 * 第一阶段删除：从查找结构中移除，但不释放内存
 * 这确保新的查找操作找不到此peer，但现有引用仍然有效
 */
static void peer_make_dead(struct wg_peer *peer)
{
	/* 从配置时的查找结构中移除 */
	list_del_init(&peer->peer_list);  // 从设备的peer链表移除
	// 从允许IP路由表中移除此peer的所有路由条目
	wg_allowedips_remove_by_peer(&peer->device->peer_allowedips, peer,
				     &peer->device->device_update_lock);
	// 从公钥哈希表中移除，新的握手请求将找不到此peer
	wg_pubkey_hashtable_remove(peer->device->peer_hashtable, peer);

	/* 原子标记为死亡状态，防止后续上下文切换时被使用 */
	WRITE_ONCE(peer->is_dead, true);

	/* 调用者必须调用synchronize_net()来确保所有CPU都看到这个更改 */
}

/**
 * peer_remove_after_dead - 在peer标记为死亡后的清理工作
 * @peer: 已标记为死亡的peer对象
 * 第二阶段删除：清理所有资源，停止定时器，刷新工作队列
 */
static void peer_remove_after_dead(struct wg_peer *peer)
{
	WARN_ON(!peer->is_dead);  // 断言：peer必须已标记为死亡

	/* 不能再为此peer创建新密钥对，因为is_dead保护了add_new_keypair，
	 * 所以现在可以安全销毁现有的密钥对。
	 */
	wg_noise_keypairs_clear(&peer->keypairs);

	/* 停止所有正在运行的定时器（握手超时、保活等），
	 * 这些定时器在函数开始时可能正在运行。
	 */
	wg_timers_stop(peer);

	/* 数据包加密/解密队列的转换不受is_dead保护，
	 * 但每个引用的生命周期严格受两代限制：
	 * 一代用于并行加密，一代用于串行处理。
	 * 所以我们可以简单地刷新两次，确保队列中不再有引用。
	 */

	/* a) 刷新加密/解密工作队列 */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.1) 刷新发送工作队列（但不是接收，因为那是napi处理） */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.2.1) 禁用NAPI接收处理（但不是发送，因为那是工作队列） */
	napi_disable(&peer->napi);
	/* b.2.2) 现在可以安全地移除NAPI结构，
	 * 这必须在进程上下文中完成。
	 */
	netif_napi_del(&peer->napi);

	/* 确保我们拥有的工作结构（如握手发送work）
	 * 不再被使用。
	 */
	flush_workqueue(peer->device->handshake_send_wq);

	/* After the above flushes, a peer might still be active in a few
	 * different contexts: 1) from xmit(), before hitting is_dead and
	 * returning, 2) from wg_packet_consume_data(), before hitting is_dead
	 * and returning, 3) from wg_receive_handshake_packet() after a point
	 * where it has processed an incoming handshake packet, but where
	 * all calls to pass it off to timers fails because of is_dead. We won't
	 * have new references in (1) eventually, because we're removed from
	 * allowedips; we won't have new references in (2) eventually, because
	 * wg_index_hashtable_lookup will always return NULL, since we removed
	 * all existing keypairs and no more can be created; we won't have new
	 * references in (3) eventually, because we're removed from the pubkey
	 * hash table, which allows for a maximum of one handshake response,
	 * via the still-uncleared index hashtable entry, but not more than one,
	 * and in wg_cookie_message_consume, the lookup eventually gets a peer
	 * with a refcount of zero, so no new reference is taken.
	 */

	--peer->device->num_peers;  // 减少设备的peer计数
	wg_peer_put(peer);          // 释放创建时获得的引用
}

/**
 * wg_peer_remove - 安全移除peer的公共接口
 * @peer: 要移除的peer对象
 * 
 * 我们有单独的"移除"函数来确保所有peer当前活跃的地方
 * 最终都会结束，不会将引用传递给另一个上下文。
 * 采用两阶段删除：先标记死亡，网络同步，再清理资源
 */
void wg_peer_remove(struct wg_peer *peer)
{
	if (unlikely(!peer))
		return;
	// 必须持有设备更新锁，确保删除过程的原子性
	lockdep_assert_held(&peer->device->device_update_lock);

	peer_make_dead(peer);    // 第一阶段：标记死亡，从查找结构移除
	synchronize_net();       // 等待所有CPU完成当前RCU临界区
	peer_remove_after_dead(peer);  // 第二阶段：清理所有资源
}

/**
 * wg_peer_remove_all - 批量移除设备的所有peer
 * @wg: WireGuard设备
 * 
 * 批量删除优化：避免逐个遍历造成的性能损失
 * 特别适用于设备关闭或重置场景
 */
void wg_peer_remove_all(struct wg_device *wg)
{
	struct wg_peer *peer, *temp;
	LIST_HEAD(dead_peers);  // 创建临时链表存储死亡的peer

	// 必须持有设备更新锁
	lockdep_assert_held(&wg->device_update_lock);

	/* 批量优化：一次性释放所有allowedips，避免逐个删除的开销 */
	wg_allowedips_free(&wg->peer_allowedips, &wg->device_update_lock);

	// 第一阶段：标记所有peer为死亡状态
	list_for_each_entry_safe(peer, temp, &wg->peer_list, peer_list) {
		peer_make_dead(peer);  // 标记死亡并从查找结构移除
		list_add_tail(&peer->peer_list, &dead_peers);  // 转移到死亡列表
	}
	// 单次网络同步，比多次调用更高效
	synchronize_net();
	// 第二阶段：批量清理所有死亡的peer
	list_for_each_entry_safe(peer, temp, &dead_peers, peer_list)
		peer_remove_after_dead(peer);
}

/**
 * rcu_release - RCU延迟释放回调函数
 * @rcu: RCU头部结构
 * 
 * 在RCU宽限期后安全释放peer内存，确保所有CPU都完成了访问
 */
static void rcu_release(struct rcu_head *rcu)
{
	struct wg_peer *peer = container_of(rcu, struct wg_peer, rcu);

	// 销毁endpoint路由缓存
	dst_cache_destroy(&peer->endpoint_cache);
	// 断言：确保发送和接收队列已完全清空
	WARN_ON(wg_prev_queue_peek(&peer->tx_queue) || wg_prev_queue_peek(&peer->rx_queue));

	/* 最终零化处理：清除所有残留的握手密钥材料
	 * 和其他潜在敏感信息，防止内存泄露攻击。
	 */
	memzero_explicit(peer, sizeof(*peer));
	// 将内存归还给专用缓存池
	kmem_cache_free(peer_cache, peer);
}

/**
 * kref_release - 引用计数归零时的最终释放函数
 * @refcount: 引用计数结构
 * 
 * 当peer的最后一个引用被释放时调用，进行最终清理
 * 不能直接释放内存，需要通过RCU延迟释放确保安全
 */
static void kref_release(struct kref *refcount)
{
	struct wg_peer *peer = container_of(refcount, struct wg_peer, refcount);

	// 调试日志：记录peer销毁，包含ID和endpoint信息
	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr);

	/* 从动态运行时查找结构中移除自己，
	 * 现在最后一个引用已经消失了。
	 */
	// 从索引哈希表中移除握手条目
	wg_index_hashtable_remove(peer->device->index_hashtable,
				  &peer->handshake.entry);

	/* 清理任何没有机会传输的滞留数据包，
	 * 这些包可能在握手期间被暂存。
	 */
	wg_packet_purge_staged_packets(peer);

	/* 通过RCU机制延迟释放内存，确保所有CPU完成访问 */
	call_rcu(&peer->rcu, rcu_release);
}

/**
 * wg_peer_put - 释放peer引用计数
 * @peer: 要释放引用的peer对象
 * 
 * 减少引用计数，当计数归零时自动触发清理流程
 * 这是peer生命周期管理的核心函数
 */
void wg_peer_put(struct wg_peer *peer)
{
	if (unlikely(!peer))
		return;
	// 原子减少引用计数，如果归零则调用kref_release进行清理
	kref_put(&peer->refcount, kref_release);
}

/**
 * wg_peer_init - 初始化peer子系统
 * 
 * 系统启动时调用，创建peer对象的专用内存缓存池
 * 返回：成功返回0，失败返回-ENOMEM
 */
int __init wg_peer_init(void)
{
	// 创建专用的slab缓存，提升peer对象分配/释放性能
	peer_cache = KMEM_CACHE(wg_peer, 0);
	return peer_cache ? 0 : -ENOMEM;
}

/**
 * wg_peer_uninit - 清理peer子系统
 * 
 * 系统关闭时调用，销毁peer对象的内存缓存池
 */
void wg_peer_uninit(void)
{
	// 销毁专用缓存池，释放所有相关内存
	kmem_cache_destroy(peer_cache);
}
