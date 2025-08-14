// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * =============================================================================
 *                        WireGuard 对等体查找子系统
 * =============================================================================
 * 
 * 本文件实现了 WireGuard 中用于快速查找对等体的两个核心哈希表：
 * 
 * 1. 公钥哈希表 (Public Key Hash Table)--aw 握手阶段
 *    - 用途：根据对等体的公钥快速查找对应的 wg_peer 结构
 *    - 场景：接收到握手消息时需要识别对等体身份
 *    - 算法：SipHash 保证安全性和均匀分布
 * 
 * 2. 索引哈希表 (Index Hash Table)  --aw 会话阶段
 *    - 用途：根据会话索引快速查找对应的密钥对和对等体
 *    - 场景：接收到数据包时需要找到解密密钥
 *    - 特点：随机索引分配避免冲突和时序攻击
 * 
 * 数据结构概览：
 * ┌──────────────────┐    ┌─────────────────┐    ┌──────────────────┐
 * │   wg_device      │    │   wg_peer       │    │  noise_keypair   │
 * │                  │    │                 │    │                  │
 * │ ┌──────────────┐ │    │ public_key ────┼────┼─► remote_static   │
 * │ │pubkey_table──┼─┼────┼─► pubkey_hash   │    │                  │
 * │ └──────────────┘ │    │                 │    │ ┌──────────────┐ │
 * │ ┌──────────────┐ │    │ handshake      │    │ │ index_hash  ──┼─┼─┐
 * │ │index_table───┼─┼────┼─► keypairs[]    │    │ │ index        │ │ │
 * │ └──────────────┘ │    │                 │    │ └──────────────┘ │ │
 * └──────────────────┘    └─────────────────┘    └──────────────────┘ │
 *                                                                     │
 *                         ┌───────────────────────────────────────────┘
 *                         ▼
 *                    Index Hash Table
 *                   ┌─────┬─────┬─────┬─────┐
 *                   │ [0] │ [1] │ ... │ [N] │  哈希桶
 *                   └─────┴─────┴─────┴─────┘
 *                      │
 *                      ▼
 *                   链表节点 (RCU保护)
 * 
 * 安全特性：
 * • 使用 RCU (Read-Copy-Update) 保证并发安全
 * • SipHash 防止哈希表碰撞攻击
 * • 随机索引分配防止时序分析
 * • 引用计数防止对等体被意外释放
 * 
 * 性能优化：
 * • O(1) 平均查找时间
 * • 最小化锁竞争 (读时无锁，写时短暂加锁)
 * • 高效的内存布局和缓存友好性
 * =============================================================================
 */

#include "peerlookup.h"
#include "peer.h"
#include "noise.h"

/*
 * =============================================================================
 *                           公钥哈希表 (Public Key Hash Table)
 * =============================================================================
 */

/**
 * pubkey_bucket - 计算公钥在哈希表中的桶位置
 * @table: 公钥哈希表指针
 * @pubkey: 要计算哈希值的公钥 (32字节)
 * 
 * 哈希算法流程：
 * ┌──────────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
 * │  Public Key  │───►│   SipHash   │───►│   64-bit     │───►│ 哈希桶索引    │
 * │   (32 bytes) │    │ (安全哈希)   │    │   哈希值     │    │ (桶数组下标)  │
 * └──────────────┘    └─────────────┘    └──────────────┘    └──────────────┘
 *                          │                     │                     │
 *                     随机密钥key           均匀分布的值        hash & (size-1)
 * 
 * 设计要点：
 * • SipHash 算法：防止哈希碰撞攻击，即使攻击者知道部分哈希值
 * • 随机密钥：每个哈希表都有唯一的随机密钥，增强安全性
 * • 位掩码操作：利用2的幂次大小，用位运算快速计算桶索引
 * • 均匀分布：SipHash 保证输出位均匀分布，避免聚集现象
 * 
 * 返回值：指向对应哈希桶的指针
 */
static struct hlist_head *pubkey_bucket(struct pubkey_hashtable *table,
					const u8 pubkey[NOISE_PUBLIC_KEY_LEN])
{
	/* 
	 * SipHash 基于随机密钥产生安全的64位哈希值
	 * 由于位均匀分布，可以直接用掩码获取所需的位数
	 */
	const u64 hash = siphash(pubkey, NOISE_PUBLIC_KEY_LEN, &table->key);

	/* 
	 * 位掩码操作：hash & (HASH_SIZE(table->hashtable) - 1)
	 * 等价于：hash % HASH_SIZE(table->hashtable)
	 * 但位运算更快，因为哈希表大小是2的幂次
	 */
	return &table->hashtable[hash & (HASH_SIZE(table->hashtable) - 1)];
}

/**
 * wg_pubkey_hashtable_alloc - 创建并初始化公钥哈希表
 * 
 * 初始化过程：
 * ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
 * │  分配内存空间   │───►│   生成随机密钥   │───►│  初始化哈希桶    │
 * │ kvmalloc()      │    │ get_random_bytes │    │  hash_init()    │
 * └─────────────────┘    └──────────────────┘    └─────────────────┘
 *                                                          │
 *                                                          ▼
 *                                                ┌─────────────────┐
 *                                                │  初始化互斥锁   │
 *                                                │ mutex_init()    │
 *                                                └─────────────────┘
 * 
 * 内存分配策略：
 * • 使用 kvmalloc(): 优先尝试连续物理内存，失败则使用虚拟内存
 * • 适合大小不定的结构，提高内存分配成功率
 * 
 * 安全性设计：
 * • 随机密钥：防止攻击者预测哈希值，避免拒绝服务攻击
 * • 互斥锁：保护哈希表结构的并发修改操作
 * 
 * 返回值：成功返回哈希表指针，失败返回 NULL
 */
struct pubkey_hashtable *wg_pubkey_hashtable_alloc(void)
{
	struct pubkey_hashtable *table = kvmalloc(sizeof(*table), GFP_KERNEL);

	if (!table)
		return NULL;

	/* 生成加密安全的随机密钥，用于 SipHash 算法 */
	get_random_bytes(&table->key, sizeof(table->key));
	
	/* 初始化所有哈希桶为空链表 */
	hash_init(table->hashtable);
	
	/* 初始化保护哈希表的互斥锁 */
	mutex_init(&table->lock);
	
	return table;
}

/**
 * wg_pubkey_hashtable_add - 将对等体添加到公钥哈希表
 * @table: 公钥哈希表指针
 * @peer: 要添加的对等体
 * 
 * 添加流程：
 * ┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐    ┌─────────────┐
 * │  获取互斥锁  │───►│  计算哈希桶位置  │───►│   插入链表头部   │───►│  释放互斥锁  │
 * │mutex_lock() │    │ pubkey_bucket() │    │hlist_add_head_rcu│    │mutex_unlock │
 * └─────────────┘    └─────────────────┘    └──────────────────┘    └─────────────┘
 *                             │                        │
 *                      基于peer->handshake      使用RCU安全链表操作
 *                      .remote_static计算       允许并发读取
 * 
 * 并发安全设计：
 * • 写操作加锁：确保哈希表结构修改的原子性
 * • RCU链表操作：允许读操作无锁并发执行
 * • 头部插入：新节点更可能被访问，提高缓存效率
 */
void wg_pubkey_hashtable_add(struct pubkey_hashtable *table,
			     struct wg_peer *peer)
{
	mutex_lock(&table->lock);
	/* 
	 * 将peer插入到对应公钥哈希值的桶中
	 * 使用RCU安全的链表操作，允许并发读取
	 */
	hlist_add_head_rcu(&peer->pubkey_hash,
			   pubkey_bucket(table, peer->handshake.remote_static));
	mutex_unlock(&table->lock);
}

/**
 * wg_pubkey_hashtable_remove - 从公钥哈希表中移除对等体
 * @table: 公钥哈希表指针  
 * @peer: 要移除的对等体
 * 
 * 移除流程：
 * ┌─────────────┐    ┌──────────────────┐    ┌─────────────┐
 * │  获取互斥锁  │───►│  从链表中删除    │───►│  释放互斥锁  │
 * │mutex_lock() │    │hlist_del_init_rcu│    │mutex_unlock │
 * └─────────────┘    └──────────────────┘    └─────────────┘
 *                             │
 *                    RCU安全删除，读者可能仍在访问
 *                    使用init版本重新初始化节点
 * 
 * 安全特性：
 * • RCU删除：不会立即释放内存，等待所有读者完成
 * • init版本：删除后重新初始化链表节点，防止悬挂指针
 * • 写保护：互斥锁确保删除操作的原子性
 */
void wg_pubkey_hashtable_remove(struct pubkey_hashtable *table,
				struct wg_peer *peer)
{
	mutex_lock(&table->lock);
	/* 
	 * RCU安全删除：不会立即破坏链表结构
	 * init版本会重新初始化节点，防止重复删除
	 */
	hlist_del_init_rcu(&peer->pubkey_hash);
	mutex_unlock(&table->lock);
}

/**
 * wg_pubkey_hashtable_lookup - 根据公钥查找对等体
 * @table: 公钥哈希表指针
 * @pubkey: 要查找的公钥 (32字节)
 * 
 * 查找流程：
 * ┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐    ┌─────────────┐
 * │  获取RCU锁  │───►│  计算哈希桶位置  │───►│   遍历链表查找   │───►│  获取引用    │
 * │rcu_read_lock│    │ pubkey_bucket() │    │hlist_for_each_   │    │wg_peer_get_ │
 * │    _bh()    │    │                 │    │  entry_rcu_bh    │    │ maybe_zero  │
 * └─────────────┘    └─────────────────┘    └──────────────────┘    └─────────────┘
 *       │                      │                        │                    │
 *    进入临界区          找到对应的哈希桶        逐个比较公钥内容         安全获取引用
 * 
 * 安全查找机制：
 * 1. RCU 读锁保护：
 *    - rcu_read_lock_bh() 防止链表在遍历时被修改
 *    - _bh 版本额外禁用软中断，保证原子性操作
 *    - 允许多个读者同时进行查找操作
 * 
 * 2. 内存比较验证：
 *    - 使用 memcmp() 按字节比较完整的32字节公钥
 *    - 确保不会因哈希碰撞而返回错误的对等体
 *    - 只有公钥完全匹配才认为找到目标
 * 
 * 3. 引用计数安全：
 *    - wg_peer_get_maybe_zero() 尝试增加引用计数
 *    - 如果对等体正在被删除（引用计数为0），返回NULL
 *    - 防止返回已经或即将被释放的对等体指针
 * 
 * 使用场景：
 * • 接收握手消息时识别发送方身份
 * • 验证对等体的身份认证信息
 * • 建立或更新加密会话时查找对应peer
 * 
 * 性能特点：
 * • 平均O(1)查找时间（SipHash保证均匀分布）
 * • 无锁读取，高并发性能优异
 * • 最坏情况O(n)（如果所有peer都哈希到同一个桶）
 * 
 * 返回值：
 * • 成功：返回匹配的wg_peer指针（已增加引用计数）
 * • 失败：返回NULL（未找到或对等体正在被删除）
 */
struct wg_peer *
wg_pubkey_hashtable_lookup(struct pubkey_hashtable *table,
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct wg_peer *iter_peer, *peer = NULL;

	/* 获取RCU读锁，禁用软中断以确保原子性 */
	rcu_read_lock_bh();
	
	/* 遍历对应哈希桶中的链表 */
	hlist_for_each_entry_rcu_bh(iter_peer, pubkey_bucket(table, pubkey),
				    pubkey_hash) {
		/* 逐字节比较公钥内容，确保精确匹配 */
		if (!memcmp(pubkey, iter_peer->handshake.remote_static,
			    NOISE_PUBLIC_KEY_LEN)) {
			peer = iter_peer;
			break;
		}
	}
	
	/* 
	 * 尝试安全获取对等体引用：
	 * - 如果peer不为NULL且引用计数>0，增加计数并返回
	 * - 如果peer为NULL或正在删除，返回NULL
	 */
	peer = wg_peer_get_maybe_zero(peer);
	
	/* 释放RCU读锁 */
	rcu_read_unlock_bh();
	return peer;
}

/*
 * =============================================================================
 *                          索引哈希表 (Index Hash Table)
 * =============================================================================
 */

/**
 * index_bucket - 计算索引在哈希表中的桶位置
 * @table: 索引哈希表指针
 * @index: 要计算哈希值的索引（32位小端格式）
 * 
 * 哈希算法原理：
 * ┌──────────────┐    ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
 * │ Random Index │───►│ Force Cast  │───►│   Bit Mask   │───►│ 哈希桶索引    │
 * │ (Little End) │    │ to u32      │    │ index & mask │    │ (桶数组下标)  │
 * └──────────────┘    └─────────────┘    └──────────────┘    └──────────────┘
 *         │                   │                   │                   │
 *    随机生成的32位         去掉字节序标记      位掩码快速取模       最终桶位置
 * 
 * 设计要点：
 * • 随机索引特性：索引值是随机生成的，所有位都均匀分布
 * • 直接位掩码：由于随机性，可以直接用位运算代替除法取模
 * • 字节序处理：__force 转换去掉 __le32 的字节序检查
 * • 2的幂次优化：哈希表大小是2的幂次，使位掩码操作有效
 * 
 * 算法优势：
 * • 极高的计算效率：单次位与运算
 * • 均匀分布：随机索引确保哈希分布均匀
 * • 无哈希算法开销：不需要复杂的哈希函数
 * 
 * 安全性：
 * • 随机索引防止攻击者预测桶位置
 * • 时序攻击防护：查找时间不泄露索引信息
 * • 均匀分布避免拒绝服务攻击
 * 
 * 返回值：指向对应哈希桶的指针
 */
static struct hlist_head *index_bucket(struct index_hashtable *table,
				       const __le32 index)
{
	/* 
	 * 由于索引是随机生成的，所有位都均匀分布，
	 * 可以直接使用位掩码找到对应的桶，无需复杂的哈希算法
	 * 
	 * (__force u32) 强制转换：去掉 __le32 的稀疏检查标记
	 * index & (size - 1)：等价于 index % size，但位运算更快
	 */
	return &table->hashtable[(__force u32)index &
				 (HASH_SIZE(table->hashtable) - 1)];
}

/**
 * wg_index_hashtable_alloc - 创建并初始化索引哈希表
 * 
 * 初始化过程：
 * ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 * │  分配内存空间   │───►│  初始化哈希桶    │───►│  初始化自旋锁   │
 * │  kvmalloc()     │    │  hash_init()    │    │ spin_lock_init  │
 * └─────────────────┘    └─────────────────┘    └─────────────────┘
 *         │                      │                      │
 *   优先物理内存         所有桶初始化为空        保护并发写操作
 * 
 * 与公钥哈希表的区别：
 * 1. 锁类型不同：
 *    - 公钥表：mutex（可睡眠，开销较大）
 *    - 索引表：spin_lock（不可睡眠，开销小）
 * 
 * 2. 无随机密钥：
 *    - 公钥表：需要随机密钥防止SipHash攻击
 *    - 索引表：索引本身就是随机的，无需额外密钥
 * 
 * 3. 访问频率：
 *    - 公钥表：主要在握手时访问（低频）
 *    - 索引表：每个数据包都要访问（高频）
 * 
 * 性能优化考虑：
 * • 自旋锁：适合短时间持锁，减少上下文切换
 * • 简单初始化：避免复杂的随机数生成
 * • 内存分配：使用kvmalloc提高分配成功率
 * 
 * 使用场景：
 * • 数据包解密时根据索引查找密钥对
 * • 会话密钥管理和轮换
 * • 快速识别数据包所属的加密会话
 * 
 * 返回值：成功返回哈希表指针，失败返回 NULL
 */
struct index_hashtable *wg_index_hashtable_alloc(void)
{
	struct index_hashtable *table = kvmalloc(sizeof(*table), GFP_KERNEL);

	if (!table)
		return NULL;

	/* 初始化所有哈希桶为空链表 */
	hash_init(table->hashtable);
	
	/* 初始化保护哈希表的自旋锁（高频访问，需要低延迟）*/
	spin_lock_init(&table->lock);
	
	return table;
}

/*
 * =============================================================================
 *                       索引分配算法性能分析
 * =============================================================================
 * 
 * 当前限制：最多支持 2^20 (约104万) 个对等体
 * 哈希表容量：大约 2^20 * 3 = 约312万个条目（每个peer可能有多个密钥对）
 * 
 * 随机索引分配算法：
 * 1. 生成一个随机的32位索引
 * 2. 检查该索引是否已被使用
 * 3. 如果冲突，重新生成随机索引，直到找到未使用的
 * 
 * 碰撞概率计算（基于生日悖论）：
 * 公式：P(k次尝试成功) = (n/2^32)^(k-1) * (1 - n/2^32)
 * 其中 n = 哈希表中已有条目数 (≈ 2^20 * 3)
 * 
 * 实际成功概率分析：
 * >>> def calculation(tries, size):
 * ...     return (size / 2**32)**(tries - 1) *  (1 - (size / 2**32))
 * 
 * 1次尝试成功：99.93% (几乎总是第一次就成功)
 * >>> calculation(1, 2**20 * 3)
 * 0.999267578125
 * 
 * 2次尝试成功：0.07% (需要重试的极少情况)
 * >>> calculation(2, 2**20 * 3)  
 * 0.0007318854331970215
 * 
 * 3次尝试成功：5.4×10^-7 (几乎不可能)
 * >>> calculation(3, 2**20 * 3)
 * 5.360489012673497e-07
 * 
 * 4次尝试成功：3.9×10^-10 (理论上不会发生)
 * >>> calculation(4, 2**20 * 3)
 * 3.9261394135792216e-10
 * 
 * 性能和安全权衡：
 * ✓ 优点：
 *   - 算法简单高效，平均1次尝试即成功
 *   - 随机性提供良好的安全特性
 *   - 对攻击者不可预测
 * 
 * ⚠ 当前限制：
 *   - 非恒定时间：尝试次数和链表长度可能泄露时序信息
 *   - 理论改进：可要求最少3次尝试来掩盖真实的成功次数
 *   - 链表长度问题：随着条目增长，查找时间会增加
 * 
 * 未来优化方向：
 * 1. 实现恒定时间查找：强制最少尝试次数
 * 2. 动态哈希表扩容：当负载因子过高时扩展桶数量
 * 3. 更好的哈希分布：使用更先进的哈希函数
 */

/**
 * wg_index_hashtable_insert - 为条目分配随机索引并插入哈希表
 * @table: 索引哈希表指针
 * @entry: 要插入的哈希表条目
 * 
 * 插入算法流程：
 * ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐
 * │ 清除旧条目  │───►│  生成随机索引   │───►│  无锁查找检查   │───►│  加锁插入    │
 * │hlist_del_   │    │get_random_u32() │    │hlist_for_each_  │    │hlist_add_   │
 * │ init_rcu    │    │                 │    │  entry_rcu_bh   │    │ head_rcu    │
 * └─────────────┘    └─────────────────┘    └─────────────────┘    └─────────────┘
 *       │                      │                      │                    │
 *  移除已存在的索引        生成新的32位随机数    检查是否已被使用       最终插入链表
 * 
 *                                 ▲                      │
 *                                 │                      ▼
 *                           ┌──────────────┐    ┌─────────────────┐
 *                           │   重试循环    │◄───│   索引冲突？     │
 *                           │search_unused │    │ existing_entry  │
 *                           │   _slot      │    │ ->index == ?    │
 *                           └──────────────┘    └─────────────────┘
 * 
 * 并发安全设计：
 * 1. 优化的锁策略：
 *    - 无锁搜索阶段：利用RCU保护，允许多线程并发搜索
 *    - 短暂加锁插入：仅在最终插入时持有锁，减少锁竞争
 *    - Double-Check模式：加锁后再次验证，防止竞态条件
 * 
 * 2. 竞态条件处理：
 *    - 场景：线程A找到空位，线程B同时插入相同索引
 *    - 解决：加锁后重新检查，如被抢占则重新开始搜索
 *    - 保证：最终一定能找到唯一的未使用索引
 * 
 * 3. RCU保护机制：
 *    - 读取保护：搜索时使用rcu_read_lock_bh()
 *    - 写入保护：插入时使用RCU安全的链表操作
 *    - 内存顺序：确保其他线程看到一致的表状态
 * 
 * 性能优化特点：
 * • 乐观并发：大部分时间无锁运行，只在必要时加锁
 * • 快速路径：99.93%的情况下一次就能找到空位
 * • 最小锁时间：持锁时间极短，只执行插入操作
 * • 软中断禁用：_bh版本防止软中断干扰
 * 
 * 安全特性：
 * • 随机索引：攻击者无法预测分配的索引值
 * • 唯一性保证：绝对避免索引重复使用
 * • 时序保护：随机重试掩盖部分时序信息
 * 
 * 返回值：分配给条目的唯一随机索引（小端格式）
 */
__le32 wg_index_hashtable_insert(struct index_hashtable *table,
				 struct index_hashtable_entry *entry)
{
	struct index_hashtable_entry *existing_entry;

	/* 
	 * 第一步：清除条目可能存在的旧索引哈希条目
	 * 如果条目之前已在表中，需要先移除避免重复
	 */
	spin_lock_bh(&table->lock);
	hlist_del_init_rcu(&entry->index_hash);
	spin_unlock_bh(&table->lock);

	/* 进入RCU读临界区，保护搜索过程 */
	rcu_read_lock_bh();

search_unused_slot:
	/* 
	 * 随机索引生成和无锁搜索阶段
	 * 在未加锁状态下尝试找到未使用的随机索引
	 */
	entry->index = (__force __le32)get_random_u32();
	
	/* 遍历对应哈希桶检查索引是否已被使用 */
	hlist_for_each_entry_rcu_bh(existing_entry,
				    index_bucket(table, entry->index),
				    index_hash) {
		if (existing_entry->index == entry->index)
			/* 索引冲突，重新生成随机索引 */
			goto search_unused_slot;
	}

	/* 
	 * 找到空位后，需要加锁并再次确认
	 * 防止在搜索和插入之间被其他线程抢占
	 */
	spin_lock_bh(&table->lock);
	
	/* Double-Check：再次验证索引确实未被使用 */
	hlist_for_each_entry_rcu_bh(existing_entry,
				    index_bucket(table, entry->index),
				    index_hash) {
		if (existing_entry->index == entry->index) {
			spin_unlock_bh(&table->lock);
			/* 被其他线程抢占，重新开始搜索 */
			goto search_unused_slot;
		}
	}
	
	/* 
	 * 确认索引唯一后，执行实际插入
	 * 由于持有锁，此时可以安全插入
	 */
	hlist_add_head_rcu(&entry->index_hash,
			   index_bucket(table, entry->index));
	spin_unlock_bh(&table->lock);

	/* 退出RCU读临界区 */
	rcu_read_unlock_bh();

	return entry->index;
}

/**
 * wg_index_hashtable_replace - 原子替换哈希表中的条目
 * @table: 索引哈希表指针
 * @old: 要被替换的旧条目
 * @new: 用来替换的新条目
 * 
 * 替换流程：
 * ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐
 * │  获取锁     │───►│  检查旧条目     │───►│  执行原子替换   │───►│  清理旧条目  │
 * │spin_lock_bh │    │!hlist_unhashed  │    │hlist_replace_   │    │INIT_HLIST_  │
 * │             │    │                 │    │    rcu          │    │   NODE      │
 * └─────────────┘    └─────────────────┘    └─────────────────┘    └─────────────┘
 *       │                      │                        │                   │
 *   保证原子性           验证条目在表中          复制索引并替换链接      防止重复使用
 * 
 * 使用场景：
 * 1. 密钥轮换：用新密钥对替换即将过期的旧密钥对
 * 2. 会话更新：更新会话状态但保持相同的索引
 * 3. 原子更新：确保查找操作不会看到不一致状态
 * 
 * 并发安全机制：
 * • 加锁保护：确保替换操作的原子性
 * • RCU替换：使用RCU安全的链表替换操作
 * • 状态验证：检查旧条目确实存在于表中
 * • 索引继承：新条目继承旧条目的索引值
 * 
 * 特殊情况处理：
 * 1. 旧条目不在表中：
 *    - 检查：hlist_unhashed(&old->index_hash) 
 *    - 结果：返回false，不执行替换
 * 
 * 2. RCU查找竞态：
 *    - 问题：替换后旧条目可能被重新插入其他位置
 *    - 影响：RCU查找可能跳桶或提前终止
 *    - 后果：数据包被丢弃（可接受的行为）
 *    - 解决：INIT_HLIST_NODE清空旧条目链接
 * 
 * 内存安全保证：
 * • 旧条目隔离：替换后立即清空链表节点
 * • RCU保护：读者不会看到悬挂指针
 * • 引用计数：调用者负责维护条目的生命周期
 * 
 * 返回值：
 * • true：成功替换
 * • false：旧条目不在表中，未执行替换
 */
bool wg_index_hashtable_replace(struct index_hashtable *table,
				struct index_hashtable_entry *old,
				struct index_hashtable_entry *new)
{
	bool ret;

	spin_lock_bh(&table->lock);
	
	/* 检查旧条目是否确实在哈希表中 */
	ret = !hlist_unhashed(&old->index_hash);
	if (unlikely(!ret))
		goto out;

	/* 新条目继承旧条目的索引值，保持查找一致性 */
	new->index = old->index;
	
	/* 执行RCU安全的原子替换操作 */
	hlist_replace_rcu(&old->index_hash, &new->index_hash);

	/* 
	 * 清空旧条目的链表节点，防止意外重用
	 * 
	 * 注意：替换完成后，旧条目理论上可能被重新插入到其他位置
	 * 这会导致RCU查找可能：
	 * 1. 提前终止（找到已清空的节点）
	 * 2. 跳转到错误的桶（如果被重新哈希）
	 * 
	 * 在这些情况下，数据包会被丢弃，这是可以接受的行为，
	 * 因为：
	 * - 不会导致安全问题（不会解密错误数据）
	 * - 网络协议具有容错性（TCP会重传，UDP本就不可靠）
	 * - 发生概率极低（需要非常特殊的时序）
	 */
	INIT_HLIST_NODE(&old->index_hash);
out:
	spin_unlock_bh(&table->lock);
	return ret;
}

/**
 * wg_index_hashtable_remove - 从索引哈希表中移除条目
 * @table: 索引哈希表指针
 * @entry: 要移除的哈希表条目
 * 
 * 移除流程：
 * ┌─────────────┐    ┌──────────────────┐    ┌─────────────┐
 * │  获取锁     │───►│  从链表中删除    │───►│  释放锁     │
 * │spin_lock_bh │    │hlist_del_init_   │    │spin_unlock_ │
 * │             │    │     rcu          │    │    bh       │
 * └─────────────┘    └──────────────────┘    └─────────────┘
 *       │                      │                      │
 *   禁用软中断保护        RCU安全删除并重置        恢复中断状态
 * 
 * 与公钥哈希表移除的对比：
 * 相似点：
 * • 都使用RCU安全的删除操作
 * • 都使用init版本重新初始化节点
 * • 都需要加锁保护写操作
 * 
 * 差异点：
 * • 锁类型：spin_lock_bh vs mutex_lock
 * • 性能：自旋锁更快，适合高频操作
 * • 使用场景：数据包处理 vs 配置管理
 * 
 * 安全特性：
 * • RCU安全：删除不会立即破坏链表结构
 * • 初始化清理：防止悬挂指针和重复删除
 * • 软中断保护：_bh版本防止网络软中断干扰
 * • 原子操作：整个删除过程是原子的
 * 
 * 使用时机：
 * • 密钥过期：旧密钥对不再需要时移除
 * • 会话结束：对等体断开连接时清理
 * • 错误处理：分配失败时的回滚操作
 * • 系统关闭：设备关闭时清理所有条目
 */
void wg_index_hashtable_remove(struct index_hashtable *table,
			       struct index_hashtable_entry *entry)
{
	spin_lock_bh(&table->lock);
	/* 
	 * RCU安全删除并重新初始化节点：
	 * - del：从链表中移除条目
	 * - init：重新初始化节点指针为NULL
	 * - rcu：确保并发读取者安全
	 */
	hlist_del_init_rcu(&entry->index_hash);
	spin_unlock_bh(&table->lock);
}

/**
 * wg_index_hashtable_lookup - 根据索引和类型查找哈希表条目
 * @table: 索引哈希表指针
 * @type_mask: 条目类型掩码，用于过滤特定类型的条目
 * @index: 要查找的索引值（小端格式）
 * @peer: 输出参数，返回找到的对等体指针
 * 
 * 查找流程：
 * ┌─────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────┐
 * │ 获取RCU锁   │──►│ 计算哈希桶位置  │──►│ 遍历链表匹配    │──►│ 验证类型    │
 * │rcu_read_    │   │ index_bucket()  │   │ index == ?      │   │type & mask  │
 * │ lock_bh()   │   │                 │   │                 │   │             │
 * └─────────────┘   └─────────────────┘   └─────────────────┘   └─────────────┘
 *       │                     │                     │                   │
 *   进入临界区           找到对应的桶         检查索引匹配         过滤条目类型
 * 
 *                                                                       │
 *                                                                       ▼
 * ┌─────────────┐   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────┐
 * │ 释放RCU锁   │◄──│  输出对等体     │◄──│  获取引用计数   │◄──│ 检查有效性  │
 * │rcu_read_    │   │  *peer =        │   │wg_peer_get_     │   │entry->peer  │
 * │unlock_bh()  │   │  entry->peer    │   │ maybe_zero()    │   │ != NULL ?   │
 * └─────────────┘   └─────────────────┘   └─────────────────┘   └─────────────┘
 * 
 * 类型掩码系统：
 * WireGuard 索引表中的条目有不同类型（定义在 noise.h 中）：
 * • INDEX_HASHTABLE_HANDSHAKE：握手过程中的临时密钥
 * • INDEX_HASHTABLE_KEYPAIR：正式的传输密钥对
 * 
 * 通过 type_mask 可以：
 * 1. 查找特定类型：type_mask = INDEX_HASHTABLE_KEYPAIR
 * 2. 查找多种类型：type_mask = HANDSHAKE | KEYPAIR
 * 3. 查找所有类型：type_mask = 0xFF
 * 
 * 双重安全检查：
 * 1. 索引匹配：确保找到正确的会话
 * 2. 类型过滤：确保条目处于期望的状态
 * 3. 引用验证：确保对等体仍然有效
 * 
 * 并发安全机制：
 * • RCU保护：允许无锁读取，与修改操作并发
 * • 引用计数：wg_peer_get_maybe_zero() 安全获取对等体引用
 * • 失效处理：如果对等体正在删除，返回NULL
 * 
 * 使用场景：
 * 1. 数据包解密：
 *    - 从数据包头解析索引
 *    - 查找对应的解密密钥
 *    - type_mask = INDEX_HASHTABLE_KEYPAIR
 * 
 * 2. 握手处理：
 *    - 处理握手响应消息
 *    - 查找握手状态信息
 *    - type_mask = INDEX_HASHTABLE_HANDSHAKE
 * 
 * 3. 会话管理：
 *    - 检查会话是否存在
 *    - 更新会话状态
 *    - type_mask = HANDSHAKE | KEYPAIR
 * 
 * 性能特点：
 * • O(1)平均查找时间：随机索引保证均匀分布
 * • 无锁读取：高并发下性能优异
 * • 软中断安全：_bh版本适合网络数据路径
 * • 快速失败：不匹配的条目立即跳过
 * 
 * 返回值：
 * • 成功：返回匹配的条目指针，*peer 设置为对等体
 * • 失败：返回NULL，*peer 不变
 */
struct index_hashtable_entry *
wg_index_hashtable_lookup(struct index_hashtable *table,
			  const enum index_hashtable_type type_mask,
			  const __le32 index, struct wg_peer **peer)
{
	struct index_hashtable_entry *iter_entry, *entry = NULL;

	/* 进入RCU读临界区，保护链表遍历 */
	rcu_read_lock_bh();
	
	/* 遍历对应哈希桶中的链表 */
	hlist_for_each_entry_rcu_bh(iter_entry, index_bucket(table, index),
				    index_hash) {
		/* 首先检查索引是否匹配 */
		if (iter_entry->index == index) {
			/* 然后检查条目类型是否符合要求 */
			if (likely(iter_entry->type & type_mask))
				entry = iter_entry;
			/* 找到匹配项就退出，无论类型是否匹配 */
			break;
		}
	}
	
	/* 如果找到了条目，尝试安全获取对等体引用 */
	if (likely(entry)) {
		/* 尝试增加对等体的引用计数 */
		entry->peer = wg_peer_get_maybe_zero(entry->peer);
		
		if (likely(entry->peer))
			/* 成功获取引用，设置输出参数 */
			*peer = entry->peer;
		else
			/* 对等体正在删除，标记查找失败 */
			entry = NULL;
	}
	
	/* 退出RCU读临界区 */
	rcu_read_unlock_bh();
	return entry;
}
