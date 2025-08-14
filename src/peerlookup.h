/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * WireGuard 对等体查找头文件
 * 
 * 定义了两个核心哈希表的数据结构和接口：
 * 1. 公钥哈希表 - 握手时根据公钥查找对等体
 * 2. 索引哈希表 - 数据传输时根据索引查找密钥对
 */

#ifndef _WG_PEERLOOKUP_H
#define _WG_PEERLOOKUP_H

#include "messages.h"

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/siphash.h>

struct wg_peer;

/* 公钥哈希表结构 */
struct pubkey_hashtable {
	/* TODO: 未来迁移到 rhashtable */
	DECLARE_HASHTABLE(hashtable, 11);  /* 2^11 = 2048个桶 */
	siphash_key_t key;                 /* SipHash随机密钥 */
	struct mutex lock;                 /* 保护表结构的互斥锁 */
};

/* 公钥哈希表操作函数 */
struct pubkey_hashtable *wg_pubkey_hashtable_alloc(void);                    /* 分配并初始化公钥哈希表 */
void wg_pubkey_hashtable_add(struct pubkey_hashtable *table,                 /* 添加对等体到哈希表 */
			     struct wg_peer *peer);
void wg_pubkey_hashtable_remove(struct pubkey_hashtable *table,              /* 从哈希表移除对等体 */
				struct wg_peer *peer);
struct wg_peer *                                                             /* 根据公钥查找对等体 */
wg_pubkey_hashtable_lookup(struct pubkey_hashtable *table,
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN]);

/* 索引哈希表结构 */
struct index_hashtable {
	/* TODO: 未来迁移到 rhashtable */
	DECLARE_HASHTABLE(hashtable, 13);  /* 2^13 = 8192个桶 */
	spinlock_t lock;                   /* 保护表结构的自旋锁 */
};

/* 索引哈希表条目类型 */
enum index_hashtable_type {
	INDEX_HASHTABLE_HANDSHAKE = 1U << 0,  /* 握手阶段的条目 */
	INDEX_HASHTABLE_KEYPAIR = 1U << 1     /* 密钥对条目 */
};

/* 索引哈希表条目结构 */
struct index_hashtable_entry {
	struct wg_peer *peer;           /* 指向对等体 */
	struct hlist_node index_hash;   /* 哈希链表节点 */
	enum index_hashtable_type type; /* 条目类型 */
	__le32 index;                   /* 索引值(小端序) */
};

/* 索引哈希表操作函数 */
struct index_hashtable *wg_index_hashtable_alloc(void);                      /* 分配并初始化索引哈希表 */
__le32 wg_index_hashtable_insert(struct index_hashtable *table,              /* 插入条目并分配随机索引 */
				 struct index_hashtable_entry *entry);
bool wg_index_hashtable_replace(struct index_hashtable *table,               /* 原子替换哈希表条目 */
				struct index_hashtable_entry *old,
				struct index_hashtable_entry *new);
void wg_index_hashtable_remove(struct index_hashtable *table,                /* 从哈希表移除条目 */
			       struct index_hashtable_entry *entry);
struct index_hashtable_entry *                                               /* 根据索引和类型查找条目 */
wg_index_hashtable_lookup(struct index_hashtable *table,
			  const enum index_hashtable_type type_mask,
			  const __le32 index, struct wg_peer **peer);

#endif /* _WG_PEERLOOKUP_H */
