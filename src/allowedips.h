/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_ALLOWEDIPS_H
#define _WG_ALLOWEDIPS_H

#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wg_peer;

struct allowedips_node {
	struct wg_peer __rcu *peer;												// 关联的对等体
	struct allowedips_node __rcu *bit[2];									// 二叉树节点指针（__rcu 注解表明使用 RCU（Read-Copy-Update）同步机制）
	u8 cidr, bit_at_a, bit_at_b, bitlen;									// CIDR 和位操作相关字段
	u8 bits[16] __aligned(__alignof(u64));									// IP 地址位数组(bits[16] 可以存储 IPv4 或 IPv6 地址)

	/* Keep rarely used members at bottom to be beyond cache line. */
	unsigned long parent_bit_packed;										// 打包的父节点位信息
	union {
		struct list_head peer_list;											// 对等体链表
		struct rcu_head rcu;												// RCU 回收头
	};
};

struct allowedips {
struct allowedips_node __rcu *root4;										// IPv4 树根节点
	struct allowedips_node __rcu *root6;									// IPv6 树根节点
	u64 seq;																// 序列号
} __aligned(4); /* We pack the lower 2 bits of &root, but m68k only gives 16-bit alignment. */

void wg_allowedips_init(struct allowedips *table);
void wg_allowedips_free(struct allowedips *table, struct mutex *mutex);

// 插入操作
int wg_allowedips_insert_v4(struct allowedips *table, const struct in_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock);
int wg_allowedips_insert_v6(struct allowedips *table, const struct in6_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock);

// 按对等体删除
void wg_allowedips_remove_by_peer(struct allowedips *table,
				  struct wg_peer *peer, struct mutex *lock);
/* The ip input pointer should be __aligned(__alignof(u64))) */
int wg_allowedips_read_node(struct allowedips_node *node, u8 ip[16], u8 *cidr);

/* These return a strong reference to a peer: */
// 查找目标地址对应的对等体
struct wg_peer *wg_allowedips_lookup_dst(struct allowedips *table,
					 struct sk_buff *skb);
// 查找源地址对应的对等体
struct wg_peer *wg_allowedips_lookup_src(struct allowedips *table,
					 struct sk_buff *skb);

#ifdef DEBUG
bool wg_allowedips_selftest(void);
#endif

int wg_allowedips_slab_init(void);
void wg_allowedips_slab_uninit(void);

#endif /* _WG_ALLOWEDIPS_H */
