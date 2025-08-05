// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * WireGuard Cookie 机制实现
 * 
 * Cookie 机制用于防止拒绝服务(DoS)攻击，通过以下方式工作：
 * 1. MAC1：消息认证码，用于验证消息的完整性和来源
 * 2. MAC2：基于 Cookie 的消息认证码，用于防止 IP 欺骗攻击
 * 3. Cookie：服务器生成的临时令牌，用于验证客户端的真实性
 * 
 * 工作流程：
 * - 正常情况下，客户端只需要提供 MAC1
 * - 当服务器检测到可能的攻击时，会要求客户端提供 Cookie
 * - 客户端必须先请求 Cookie，然后在后续消息中包含基于 Cookie 的 MAC2
 */

#include "cookie.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "ratelimiter.h"
#include "timers.h"

#include <zinc/blake2s.h>
#include <zinc/chacha20poly1305.h>

#include <net/ipv6.h>
#include <crypto/algapi.h>

/*
 * 初始化 Cookie 检查器
 * @checker: 要初始化的 Cookie 检查器
 * @wg: 关联的 WireGuard 设备
 * 
 * 此函数设置 Cookie 检查器的初始状态，包括：
 * - 初始化读写信号量保护密钥访问
 * - 记录密钥生成时间
 * - 生成随机密钥用于 Cookie 生成
 */
void wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg)
{
	init_rwsem(&checker->secret_lock);                      // 初始化读写锁，保护密钥访问
	checker->secret_birthdate = ktime_get_coarse_boottime_ns(); // 记录密钥生成时间戳
	get_random_bytes(checker->secret, NOISE_HASH_LEN);      // 生成随机密钥，用于 Cookie 计算
	checker->device = wg;                                   // 关联到 WireGuard 设备
}

// 密钥标签长度常量
enum { COOKIE_KEY_LABEL_LEN = 8 };

// 预定义的密钥派生标签
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";    // MAC1 密钥派生标签
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";  // Cookie 密钥派生标签

/*
 * 预计算加密密钥
 * @key: 输出的对称密钥
 * @pubkey: 公钥，用于密钥派生
 * @label: 密钥派生标签
 * 
 * 使用 BLAKE2s 哈希函数从公钥和标签派生对称密钥
 * 密钥派生公式：key = BLAKE2s(label || pubkey)
 */
static void precompute_key(u8 key[NOISE_SYMMETRIC_KEY_LEN],
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 label[COOKIE_KEY_LABEL_LEN])
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);          // 初始化 BLAKE2s 状态，输出长度为对称密钥长度
	blake2s_update(&blake, label, COOKIE_KEY_LABEL_LEN);    // 输入标签到哈希计算
	blake2s_update(&blake, pubkey, NOISE_PUBLIC_KEY_LEN);   // 输入公钥到哈希计算
	blake2s_final(&blake, key);                             // 完成哈希计算，输出密钥
}

/*
 * 预计算设备相关的加密密钥
 * @checker: Cookie 检查器
 * 
 * 注意：调用前必须持有 peer->handshake.static_identity->lock 锁
 * 
 * 根据设备的静态公钥预计算两个重要密钥：
 * 1. cookie_encryption_key：用于加密/解密 Cookie 消息
 * 2. message_mac1_key：用于计算和验证 MAC1
 */
void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker)
{
	if (likely(checker->device->static_identity.has_identity)) {
		// 设备有静态身份，预计算 Cookie 加密密钥
		precompute_key(checker->cookie_encryption_key,
			       checker->device->static_identity.static_public,
			       cookie_key_label);
		// 预计算 MAC1 验证密钥
		precompute_key(checker->message_mac1_key,
			       checker->device->static_identity.static_public,
			       mac1_key_label);
	} else {
		// 设备没有静态身份，清零密钥
		memset(checker->cookie_encryption_key, 0,
		       NOISE_SYMMETRIC_KEY_LEN);
		memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
	}
}

/*
 * 预计算对等体相关的加密密钥
 * @peer: 目标对等体
 * 
 * 根据对等体的静态公钥预计算两个密钥：
 * 1. cookie_decryption_key：用于解密来自该对等体的 Cookie 消息
 * 2. message_mac1_key：用于验证来自该对等体的 MAC1
 */
void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	// 基于对等体的远程静态公钥预计算 Cookie 解密密钥
	precompute_key(peer->latest_cookie.cookie_decryption_key,
		       peer->handshake.remote_static, cookie_key_label);
	// 基于对等体的远程静态公钥预计算 MAC1 密钥
	precompute_key(peer->latest_cookie.message_mac1_key,
		       peer->handshake.remote_static, mac1_key_label);
}

/*
 * 初始化 Cookie 结构
 * @cookie: 要初始化的 Cookie 结构
 * 
 * 清零 Cookie 结构并初始化其读写锁
 */
void wg_cookie_init(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));     // 清零整个 Cookie 结构
	init_rwsem(&cookie->lock);              // 初始化读写信号量，保护 Cookie 访问
}

/*
 * 计算消息的 MAC1 值
 * @mac1: 输出的 MAC1 值
 * @message: 要计算 MAC 的消息
 * @len: 消息总长度
 * @key: MAC 计算密钥
 * 
 * MAC1 是消息的认证码，用于验证消息完整性和来源
 * 计算范围：消息开头到 MAC1 字段之前的所有内容
 */
static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len,
			 const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
	// 计算需要包含在 MAC1 计算中的消息长度
	// 排除整个 message_macs 结构，但包含到 mac1 字段的偏移
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac1);
	// 使用 BLAKE2s 计算 MAC1
	blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);
}

/*
 * 计算消息的 MAC2 值
 * @mac2: 输出的 MAC2 值
 * @message: 要计算 MAC 的消息
 * @len: 消息总长度
 * @cookie: 用作密钥的 Cookie 值
 * 
 * MAC2 是基于 Cookie 的消息认证码，用于防止 IP 欺骗攻击
 * 计算范围：消息开头到 MAC2 字段之前的所有内容（包括 MAC1）
 */
static void compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len,
			 const u8 cookie[COOKIE_LEN])
{
	// 计算需要包含在 MAC2 计算中的消息长度
	// 排除整个 message_macs 结构，但包含到 mac2 字段的偏移
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac2);
	// 使用 BLAKE2s 计算 MAC2，以 Cookie 作为密钥
	blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
}

/*
 * 生成 Cookie 值
 * @cookie: 输出的 Cookie 值
 * @skb: 网络数据包，用于提取源地址和端口
 * @checker: Cookie 检查器，包含生成 Cookie 的密钥
 * 
 * Cookie 是基于客户端 IP 地址和端口生成的临时令牌
 * 生成公式：Cookie = BLAKE2s(secret, src_ip || src_port)
 * 
 * Cookie 机制防止 IP 欺骗：攻击者无法为虚假 IP 地址生成有效 Cookie
 */
static void make_cookie(u8 cookie[COOKIE_LEN], struct sk_buff *skb,
			struct cookie_checker *checker)
{
	struct blake2s_state state;

	// 检查密钥是否过期，如果过期则重新生成
	if (wg_birthdate_has_expired(checker->secret_birthdate,
				     COOKIE_SECRET_MAX_AGE)) {
		down_write(&checker->secret_lock);                  // 获取写锁
		checker->secret_birthdate = ktime_get_coarse_boottime_ns(); // 更新密钥生成时间
		get_random_bytes(checker->secret, NOISE_HASH_LEN);  // 生成新的随机密钥
		up_write(&checker->secret_lock);                    // 释放写锁
	}

	down_read(&checker->secret_lock);                           // 获取读锁访问密钥

	// 使用密钥初始化 BLAKE2s 状态
	blake2s_init_key(&state, COOKIE_LEN, checker->secret, NOISE_HASH_LEN);
	
	// 根据数据包类型添加源 IP 地址到哈希计算
	if (skb->protocol == htons(ETH_P_IP))
		blake2s_update(&state, (u8 *)&ip_hdr(skb)->saddr,
			       sizeof(struct in_addr));              // IPv4 源地址
	else if (skb->protocol == htons(ETH_P_IPV6))
		blake2s_update(&state, (u8 *)&ipv6_hdr(skb)->saddr,
			       sizeof(struct in6_addr));             // IPv6 源地址
	
	// 添加源端口到哈希计算
	blake2s_update(&state, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));
	blake2s_final(&state, cookie);                              // 完成计算，输出 Cookie

	up_read(&checker->secret_lock);                             // 释放读锁
}

/*
 * 验证数据包的 MAC 和 Cookie
 * @checker: Cookie 检查器
 * @skb: 要验证的网络数据包
 * @check_cookie: 是否检查 Cookie（MAC2）
 * 
 * 返回值说明：
 * - INVALID_MAC: MAC1 无效
 * - VALID_MAC_BUT_NO_COOKIE: MAC1 有效但未检查 Cookie
 * - VALID_MAC_WITH_COOKIE_BUT_RATELIMITED: MAC1 和 Cookie 都有效但被限流
 * - VALID_MAC_WITH_COOKIE: 所有验证都通过
 * 
 * 验证流程：
 * 1. 验证 MAC1（基本消息完整性）
 * 2. 如果需要，验证 MAC2（基于 Cookie 的防欺骗）
 * 3. 检查速率限制
 */
enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie)
{
	struct message_macs *macs = (struct message_macs *)
		(skb->data + skb->len - sizeof(*macs));             // 获取数据包末尾的 MAC 结构
	enum cookie_mac_state ret;
	u8 computed_mac[COOKIE_LEN];
	u8 cookie[COOKIE_LEN];

	ret = INVALID_MAC;
	// 第一步：验证 MAC1
	compute_mac1(computed_mac, skb->data, skb->len,
		     checker->message_mac1_key);                    // 计算预期的 MAC1
	if (crypto_memneq(computed_mac, macs->mac1, COOKIE_LEN))    // 比较 MAC1
		goto out;                                           // MAC1 不匹配，返回 INVALID_MAC

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)                                          // 如果不需要检查 Cookie
		goto out;                                           // 返回 VALID_MAC_BUT_NO_COOKIE

	// 第二步：验证 MAC2（Cookie）
	make_cookie(cookie, skb, checker);                          // 生成期望的 Cookie

	compute_mac2(computed_mac, skb->data, skb->len, cookie);    // 计算预期的 MAC2
	if (crypto_memneq(computed_mac, macs->mac2, COOKIE_LEN))    // 比较 MAC2
		goto out;                                           // MAC2 不匹配，返回 VALID_MAC_BUT_NO_COOKIE

	// 第三步：检查速率限制
	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!wg_ratelimiter_allow(skb, dev_net(checker->device->dev))) // 检查速率限制
		goto out;                                           // 被限流，返回相应状态

	ret = VALID_MAC_WITH_COOKIE;                                // 所有检查都通过

out:
	return ret;
}

/*
 * 为发送的消息添加 MAC 认证码
 * @message: 要添加 MAC 的消息
 * @len: 消息长度
 * @peer: 目标对等体
 * 
 * 此函数为出站消息添加 MAC1 和 MAC2：
 * 1. MAC1：始终计算，用于基本消息认证
 * 2. MAC2：仅在有有效 Cookie 时计算，用于防止 IP 欺骗
 */
void wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer)
{
	struct message_macs *macs = (struct message_macs *)
		((u8 *)message + len - sizeof(*macs));             // 获取消息末尾的 MAC 结构

	// 计算并设置 MAC1
	down_write(&peer->latest_cookie.lock);                      // 获取写锁
	compute_mac1(macs->mac1, message, len,
		     peer->latest_cookie.message_mac1_key);         // 计算 MAC1
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN); // 保存发送的 MAC1
	peer->latest_cookie.have_sent_mac1 = true;                  // 标记已发送 MAC1
	up_write(&peer->latest_cookie.lock);                        // 释放写锁

	// 计算并设置 MAC2（如果有有效的 Cookie）
	down_read(&peer->latest_cookie.lock);                       // 获取读锁
	if (peer->latest_cookie.is_valid &&                         // Cookie 有效
	    !wg_birthdate_has_expired(peer->latest_cookie.birthdate, // 且未过期
				COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len,              // 计算 MAC2
			     peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);                  // 清零 MAC2（无有效 Cookie）
	up_read(&peer->latest_cookie.lock);                         // 释放读锁
}

/*
 * 创建 Cookie 消息
 * @dst: 输出的 Cookie 消息结构
 * @skb: 触发 Cookie 请求的原始数据包
 * @index: 接收方索引
 * @checker: Cookie 检查器
 * 
 * 当服务器需要客户端提供 Cookie 时，创建并发送此消息
 * Cookie 消息包含：
 * 1. 消息类型（MESSAGE_HANDSHAKE_COOKIE）
 * 2. 接收方索引
 * 3. 随机 nonce
 * 4. 加密的 Cookie 值
 */
void wg_cookie_message_create(struct message_handshake_cookie *dst,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker)
{
	struct message_macs *macs = (struct message_macs *)
		((u8 *)skb->data + skb->len - sizeof(*macs));       // 获取原始消息的 MAC
	u8 cookie[COOKIE_LEN];

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE);   // 设置消息类型
	dst->receiver_index = index;                                // 设置接收方索引
	get_random_bytes_wait(dst->nonce, COOKIE_NONCE_LEN);        // 生成随机 nonce

	make_cookie(cookie, skb, checker);                          // 为请求方生成 Cookie
	// 使用 XChaCha20-Poly1305 加密 Cookie，以原始消息的 MAC1 作为关联数据
	xchacha20poly1305_encrypt(dst->encrypted_cookie, cookie, COOKIE_LEN,
				  macs->mac1, COOKIE_LEN, dst->nonce,
				  checker->cookie_encryption_key);
}

/*
 * 处理接收到的 Cookie 消息
 * @src: 接收到的 Cookie 消息
 * @wg: WireGuard 设备
 * 
 * 当客户端收到服务器的 Cookie 消息时，解密并保存 Cookie
 * 用于后续消息的 MAC2 计算，以通过服务器的防 DoS 检查
 */
void wg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct wg_device *wg)
{
	struct wg_peer *peer = NULL;
	u8 cookie[COOKIE_LEN];
	bool ret;

	// 根据接收方索引查找对应的对等体
	if (unlikely(!wg_index_hashtable_lookup(wg->index_hashtable,
						INDEX_HASHTABLE_HANDSHAKE |
						INDEX_HASHTABLE_KEYPAIR,
						src->receiver_index, &peer)))
		return;                                             // 找不到对等体，直接返回

	down_read(&peer->latest_cookie.lock);                       // 获取读锁
	if (unlikely(!peer->latest_cookie.have_sent_mac1)) {        // 检查是否发送过 MAC1
		up_read(&peer->latest_cookie.lock);                 // 如果没有发送过 MAC1，
		goto out;                                           // 则不应该收到 Cookie 消息
	}
	// 尝试解密 Cookie，使用上次发送的 MAC1 作为关联数据
	ret = xchacha20poly1305_decrypt(
		cookie, src->encrypted_cookie, sizeof(src->encrypted_cookie),
		peer->latest_cookie.last_mac1_sent, COOKIE_LEN, src->nonce,
		peer->latest_cookie.cookie_decryption_key);
	up_read(&peer->latest_cookie.lock);                         // 释放读锁

	if (ret) {                                                  // 解密成功
		down_write(&peer->latest_cookie.lock);              // 获取写锁
		memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN); // 保存 Cookie
		peer->latest_cookie.birthdate = ktime_get_coarse_boottime_ns(); // 记录时间戳
		peer->latest_cookie.is_valid = true;                // 标记 Cookie 有效
		peer->latest_cookie.have_sent_mac1 = false;         // 重置 MAC1 发送标志
		up_write(&peer->latest_cookie.lock);                // 释放写锁
	} else {                                                    // 解密失败
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response\n",
				    wg->dev->name);                 // 记录调试信息
	}

out:
	wg_peer_put(peer);                                          // 释放对等体引用
}
