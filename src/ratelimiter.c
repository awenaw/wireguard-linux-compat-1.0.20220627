// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * ===================================================================
 * WireGuard 速率限制器 (Rate Limiter)
 * ===================================================================
 * 
 * 本文件实现了 WireGuard 的高性能速率限制系统，用于防止 DoS 攻击和
 * 恶意流量滥用。采用令牌桶算法和高效哈希表结构，支持 IPv4/IPv6，
 * 提供精确的每IP速率控制。
 * 
 * 核心设计理念：
 * 1. 防DoS攻击 - 限制每个源IP的包速率
 * 2. 高性能 - 基于RCU的无锁读取
 * 3. 内存高效 - 自动垃圾回收过期条目
 * 4. 公平性 - 令牌桶算法保证公平调度
 * 5. 可扩展 - 根据系统内存动态调整哈希表大小
 * 
 * 整体架构图：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                WireGuard 速率限制器架构                      │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │ ┌─────────────┐              ┌─────────────┐                │
 * │ │ 数据包输入   │ ──────────→ │ IP地址提取   │                │
 * │ │ (UDP包)     │              │ & 哈希计算  │                │
 * │ └─────────────┘              └─────────────┘                │
 * │                                     │                      │
 * │                                     ▼                      │
 * │ ┌───────────────────────────────────────────────────────┐  │
 * │ │                哈希表查找                              │  │
 * │ │   IPv4 Table        IPv6 Table                       │  │
 * │ │  ┌─────────────┐    ┌─────────────┐                  │  │
 * │ │  │bucket[0]    │    │bucket[0]    │                  │  │
 * │ │  │ ┌─────────┐ │    │ ┌─────────┐ │                  │  │
 * │ │  │ │Entry    │ │    │ │Entry    │ │                  │  │
 * │ │  │ │tokens=X │ │    │ │tokens=Y │ │                  │  │
 * │ │  │ └─────────┘ │    │ └─────────┘ │                  │  │
 * │ │  │bucket[1]    │    │bucket[1]    │                  │  │
 * │ │  │bucket[...]  │    │bucket[...]  │                  │  │
 * │ │  └─────────────┘    └─────────────┘                  │  │
 * │ └───────────────────────────────────────────────────────┘  │
 * │                             │                              │
 * │        ┌───────────────────────────────────┐                │
 * │        ▼                                   │                │
 * │ ┌─────────────┐                    ┌─────────────┐         │
 * │ │ 条目存在     │                    │ 条目不存在   │         │
 * │ │             │                    │             │         │
 * │ │ • 令牌桶     │                    │ • 创建新条目 │         │
 * │ │   更新计算   │                    │ • 初始化令牌 │         │
 * │ │ • 速率检查   │                    │ • 插入哈希表 │         │
 * │ └─────────────┘                    └─────────────┘         │
 * │        │                                   │                │
 * │        └───────────────────────────────────┘                │
 * │                             │                              │
 * │                             ▼                              │
 * │                  ┌─────────────────┐                       │
 * │                  │   返回决策结果   │                       │
 * │                  │  true: 允许     │                       │
 * │                  │  false: 拒绝    │                       │
 * │                  └─────────────────┘                       │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 令牌桶算法原理：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    令牌桶算法示意图                          │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │   令牌生成器              令牌桶                 包处理器     │
 * │  (固定速率)              (有限容量)               (消费)      │
 * │      │                     │                      │        │
 * │      ▼                     ▼                      ▼        │
 * │  ┌─────────┐          ┌─────────────┐         ┌─────────┐   │
 * │  │ 20 tok/s│ ──────→ │ [●●●○○]     │ ──────→ │ 1 tok   │   │
 * │  │ 生成速率 │          │ 最大5个令牌  │         │ 每包消耗 │   │
 * │  └─────────┘          └─────────────┘         └─────────┘   │
 * │                             │                              │
 * │                             ▼                              │
 * │                    ┌─────────────────┐                     │
 * │                    │   决策逻辑:      │                     │
 * │                    │   if (tokens≥1) │                     │
 * │                    │     允许 & -1   │                     │
 * │                    │   else          │                     │
 * │                    │     拒绝        │                     │
 * │                    └─────────────────┘                     │
 * │                                                             │
 * │  特性：                                                     │
 * │  • 平均速率：20 包/秒                                       │
 * │  • 突发容量：5 包                                          │
 * │  • 令牌恢复：50ms/令牌                                      │
 * │  • 过载保护：自动限流                                       │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 垃圾回收机制：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                     内存管理策略                             │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  定期清理 (每秒执行)：                                       │
 * │                                                             │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │               垃圾回收器                             │   │
 * │  │                                                     │   │
 * │  │  遍历所有哈希桶 → 检查条目年龄 → 删除过期条目         │   │
 * │  │       │                │              │             │   │
 * │  │       ▼                ▼              ▼             │   │
 * │  │  for (i=0;         if (now -      hlist_del_rcu()   │   │
 * │  │     i<size;        entry->time    call_rcu()        │   │
 * │  │     i++)           > 1sec)                          │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │                                                             │
 * │  内存保护：                                                 │
 * │  • 最大条目数限制 (table_size * 8)                          │
 * │  • RCU延迟释放避免竞争                                      │
 * │  • kmem_cache提高分配效率                                   │
 * │  • 原子计数跟踪内存使用                                     │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 性能特性：
 * 1. 无锁读取 - RCU保护的哈希表查找
 * 2. 高效哈希 - SipHash保证安全性和速度
 * 3. 内存池化 - kmem_cache减少分配开销
 * 4. 自适应大小 - 根据系统RAM动态调整
 * 5. 延迟清理 - 后台垃圾回收不影响快速路径
 * 
 * 安全特性：
 * 1. DoS防护 - 严格的每IP速率限制
 * 2. 哈希安全 - 随机密钥防止哈希碰撞攻击
 * 3. 内存保护 - 条目数量上限防止内存耗尽
 * 4. 网络隔离 - 支持网络命名空间隔离
 * 5. IPv6支持 - /64子网级别的速率限制
 */

#ifdef COMPAT_CANNOT_DEPRECIATE_BH_RCU
/* We normally alias all non-_bh functions to the _bh ones in the compat layer,
 * but that's not appropriate here, where we actually do want non-_bh ones.
 * 
 * 兼容性说明：
 * 通常在兼容层中我们将所有非_bh函数别名为_bh版本，但在这里不合适，
 * 因为我们确实需要非_bh版本的RCU函数。速率限制器运行在进程上下文中，
 * 不需要底半部禁用保护。
 */
#undef synchronize_rcu
#define synchronize_rcu old_synchronize_rcu
#undef call_rcu
#define call_rcu old_call_rcu
#undef rcu_barrier
#define rcu_barrier old_rcu_barrier
#endif

#include "ratelimiter.h"
#include <linux/siphash.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <net/ip.h>

/*
 * ===================================================================
 * 全局数据结构和配置
 * ===================================================================
 */

static struct kmem_cache *entry_cache;        /* 速率限制条目的内存缓存池 */
static hsiphash_key_t key;                    /* SipHash哈希计算的随机密钥 */
static spinlock_t table_lock = __SPIN_LOCK_UNLOCKED("ratelimiter_table_lock");
                                              /* 哈希表修改保护锁 */
static DEFINE_MUTEX(init_lock);               /* 初始化/清理过程互斥锁 */
static u64 init_refcnt;                       /* 初始化引用计数 (由init_lock保护) */
static atomic_t total_entries = ATOMIC_INIT(0); /* 当前条目总数 (原子计数器) */
static unsigned int max_entries, table_size;  /* 最大条目数和哈希表大小 */
static void wg_ratelimiter_gc_entries(struct work_struct *);
static DECLARE_DEFERRABLE_WORK(gc_work, wg_ratelimiter_gc_entries);
                                              /* 可延迟的垃圾回收工作队列 */
static struct hlist_head *table_v4;          /* IPv4 哈希表 */
#if IS_ENABLED(CONFIG_IPV6)
static struct hlist_head *table_v6;          /* IPv6 哈希表 (如果启用IPv6) */
#endif

/*
 * ===================================================================
 * 速率限制条目数据结构
 * ===================================================================
 */

/**
 * struct ratelimiter_entry - 单个IP地址的速率限制条目
 * 
 * 功能描述：
 * 每个唯一的 (网络命名空间, IP地址) 组合对应一个速率限制条目。
 * 该结构体实现了令牌桶算法，跟踪每个IP的包发送速率。
 * 
 * 条目生命周期：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                   条目生命周期管理                           │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  创建 → 使用 → 老化 → 删除                                  │
 * │   │      │      │      │                                   │
 * │   ▼      ▼      ▼      ▼                                   │
 * │ 分配   更新   闲置   RCU                                    │
 * │ 内存   令牌   超时   释放                                    │
 * │                                                             │
 * │ 详细流程：                                                   │
 * │ 1. kmem_cache_alloc() - 从缓存池分配                         │
 * │ 2. 初始化字段和令牌桶                                        │
 * │ 3. hlist_add_head_rcu() - 插入哈希表                        │
 * │ 4. 定期令牌更新和速率检查                                    │
 * │ 5. 超过1秒未使用视为过期                                     │
 * │ 6. hlist_del_rcu() + call_rcu() - 安全删除                 │
 * └─────────────────────────────────────────────────────────────┘
 */
struct ratelimiter_entry {
	u64 last_time_ns;                  /* 最后一次访问时间 (纳秒时间戳)
	                                    * 用于：令牌桶更新计算和垃圾回收
	                                    * 来源：ktime_get_coarse_boottime_ns()
	                                    * 精度：粗粒度时间，性能优化
	                                    */
	                                    
	u64 tokens;                        /* 当前可用令牌数 (纳秒单位)
	                                    * 范围：0 到 TOKEN_MAX
	                                    * 计算：根据时间差线性增加
	                                    * 消耗：每包消耗 PACKET_COST
	                                    */
	                                    
	u64 ip;                            /* IP地址 (主机字节序)
	                                    * IPv4：32位地址扩展为64位
	                                    * IPv6：前64位(/64子网)
	                                    * 用途：哈希表查找键值
	                                    */
	                                    
	void *net;                         /* 网络命名空间指针
	                                    * 用途：隔离不同网络命名空间
	                                    * 类型：struct net* 但声明为void*
	                                    * 比较：指针值直接比较
	                                    */
	                                    
	spinlock_t lock;                   /* 条目级别的自旋锁
	                                    * 保护：tokens, last_time_ns字段
	                                    * 范围：令牌更新的关键区域
	                                    * 特性：嵌套在table_lock内部
	                                    */
	                                    
	struct hlist_node hash;            /* 哈希表链表节点
	                                    * 用途：链接到哈希桶中
	                                    * 操作：hlist_add_head_rcu/del_rcu
	                                    * 保护：RCU读-复制-更新机制
	                                    */
	                                    
	struct rcu_head rcu;               /* RCU延迟释放头
	                                    * 用途：安全的内存回收
	                                    * 机制：call_rcu延迟调用
	                                    * 回调：entry_free函数
	                                    */
};

/*
 * ===================================================================
 * 速率限制参数配置
 * ===================================================================
 */

/**
 * enum - 速率限制算法参数
 * 
 * 参数说明：
 * 这些参数定义了令牌桶算法的行为特性，平衡了安全性和可用性。
 * 
 * 算法参数关系图：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                  令牌桶参数计算关系                          │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  PACKETS_PER_SECOND = 20 包/秒                              │
 * │         │                                                   │
 * │         ▼                                                   │
 * │  PACKET_COST = 1秒 ÷ 20 = 50,000,000 纳秒/包               │
 * │         │                                                   │
 * │         ▼                                                   │
 * │  PACKETS_BURSTABLE = 5 包                                   │
 * │         │                                                   │
 * │         ▼                                                   │
 * │  TOKEN_MAX = 50ms × 5 = 250,000,000 纳秒                   │
 * │                                                             │
 * │  含义解释：                                                 │
 * │  • 平均每50ms可发送1包                                      │
 * │  • 最多可突发5包后必须等待                                  │
 * │  • 空闲250ms后可达到最大突发能力                            │
 * │  • 持续发送时平均速率为20包/秒                              │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 安全考虑：
 * - 20包/秒足以处理正常握手重试
 * - 5包突发能力允许短暂的合理突发
 * - 参数较为保守，优先安全性而非性能
 * - 可防止低速率的持续DoS攻击
 */
enum {
	PACKETS_PER_SECOND = 20,           /* 平均允许速率：每秒20包
	                                    * 依据：正常WireGuard握手频率
	                                    * 平衡：足够正常使用，限制滥用
	                                    * 对比：典型防火墙限制为10-50包/秒
	                                    */
	                                    
	PACKETS_BURSTABLE = 5,             /* 允许突发包数：5包
	                                    * 含义：短时间内可连续发送5包
	                                    * 用途：处理网络抖动和重传
	                                    * 恢复：需要250ms才能重新突发
	                                    */
	                                    
	PACKET_COST = NSEC_PER_SEC / PACKETS_PER_SECOND,
	                                   /* 每包令牌成本：50,000,000纳秒
	                                    * 计算：1,000,000,000ns ÷ 20 = 50ms
	                                    * 含义：发送1包需要消耗50ms的令牌
	                                    * 单位：纳秒 (与时间戳保持一致)
	                                    */
	                                    
	TOKEN_MAX = PACKET_COST * PACKETS_BURSTABLE
	                                   /* 令牌桶最大容量：250,000,000纳秒
	                                    * 计算：50ms × 5包 = 250ms
	                                    * 含义：最多可累积250ms的发送能力
	                                    * 饱和：空闲250ms后达到满桶状态
	                                    */
};

static void entry_free(struct rcu_head *rcu)
{
	kmem_cache_free(entry_cache,
			container_of(rcu, struct ratelimiter_entry, rcu));
	atomic_dec(&total_entries);
}

static void entry_uninit(struct ratelimiter_entry *entry)
{
	hlist_del_rcu(&entry->hash);
	call_rcu(&entry->rcu, entry_free);
}

/* Calling this function with a NULL work uninits all entries. */
static void wg_ratelimiter_gc_entries(struct work_struct *work)
{
	const u64 now = ktime_get_coarse_boottime_ns();
	struct ratelimiter_entry *entry;
	struct hlist_node *temp;
	unsigned int i;

	for (i = 0; i < table_size; ++i) {
		spin_lock(&table_lock);
		hlist_for_each_entry_safe(entry, temp, &table_v4[i], hash) {
			if (unlikely(!work) ||
			    now - entry->last_time_ns > NSEC_PER_SEC)
				entry_uninit(entry);
		}
#if IS_ENABLED(CONFIG_IPV6)
		hlist_for_each_entry_safe(entry, temp, &table_v6[i], hash) {
			if (unlikely(!work) ||
			    now - entry->last_time_ns > NSEC_PER_SEC)
				entry_uninit(entry);
		}
#endif
		spin_unlock(&table_lock);
		if (likely(work))
			cond_resched();
	}
	if (likely(work))
		queue_delayed_work(system_power_efficient_wq, &gc_work, HZ);
}

/*
 * ===================================================================
 * 核心速率限制判断函数
 * ===================================================================
 */

/**
 * wg_ratelimiter_allow - 检查数据包是否被速率限制允许
 * @skb: 网络数据包结构指针
 * @net: 网络命名空间指针
 * 
 * 返回值：true表示允许包通过，false表示应丢弃包
 * 
 * 功能描述：
 * 这是速率限制器的核心函数，实现基于IP地址的令牌桶速率控制。
 * 支持IPv4和IPv6，具有高性能哈希查找和无锁读取优化。
 * 
 * 处理流程图：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                   速率限制检查流程                           │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  输入：数据包 + 网络命名空间                                │
 * │     │                                                       │
 * │     ▼                                                       │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │                 IP地址提取                           │   │
 * │  │  IPv4: ip_hdr(skb)->saddr (32位)                   │   │
 * │  │  IPv6: ipv6_hdr(skb)->saddr[0:63] (64位/64子网)     │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │     │                                                       │
 * │     ▼                                                       │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │                哈希计算和桶定位                      │   │
 * │  │  hash = siphash(net_word, ip) & (table_size - 1)   │   │
 * │  │  bucket = table[hash]                               │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │     │                                                       │
 * │     ▼                                                       │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │            RCU保护的哈希表遍历                       │   │
 * │  │  for each entry in bucket:                          │   │
 * │  │    if (entry->net == net && entry->ip == ip)       │   │
 * │  │      found!                                         │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │     │                     │                               │
 * │  找到条目                  未找到条目                       │
 * │     │                     │                               │
 * │     ▼                     ▼                               │
 * │  ┌─────────────┐    ┌─────────────┐                       │
 * │  │ 令牌桶更新   │    │ 创建新条目   │                       │
 * │  │ 和速率检查   │    │ 和初始化     │                       │
 * │  └─────────────┘    └─────────────┘                       │
 * │     │                     │                               │
 * │     └─────────┬───────────┘                               │
 * │               ▼                                           │
 * │        返回允许/拒绝决策                                    │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 哈希优化设计：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    SipHash优化策略                          │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  网络命名空间指针优化：                                      │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │  完整指针: 0x12345678_ABCDEF00 (64位)              │   │
 * │  │  取低半部: 0xABCDEF00 (32位)                       │   │
 * │  │  优势: 减少哈希输入长度，提升性能                   │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │                                                             │
 * │  哈希输入组合：                                             │
 * │  IPv4: siphash_2u32(net_word, ip, &key)                    │
 * │       [32位网络] + [32位IPv4地址] = 2×32位输入              │
 * │                                                             │
 * │  IPv6: siphash_3u32(net_word, ip>>32, ip, &key)            │
 * │       [32位网络] + [32位IPv6高位] + [32位IPv6低位]          │
 * │       = 3×32位输入                                          │
 * │                                                             │
 * │  性能优势：                                                 │
 * │  • 输入长度恰好填满SipHash参数                              │
 * │  • 避免额外的哈希轮数                                       │
 * │  • 保持哈希质量和安全性                                     │
 * └─────────────────────────────────────────────────────────────┘
 */
bool wg_ratelimiter_allow(struct sk_buff *skb, struct net *net)
{
	/* We only take the bottom half of the net pointer, so that we can hash
	 * 3 words in the end. This way, siphash's len param fits into the final
	 * u32, and we don't incur an extra round.
	 * 
	 * 性能优化：只使用网络命名空间指针的低半部分进行哈希计算。
	 * 这样可以精确控制SipHash的输入长度，避免额外的哈希计算轮数。
	 */
	const u32 net_word = (unsigned long)net;
	struct ratelimiter_entry *entry;
	struct hlist_head *bucket;
	u64 ip;

	/* IPv4协议处理 */
	if (skb->protocol == htons(ETH_P_IP)) {
		ip = (u64 __force)ip_hdr(skb)->saddr;              /* 提取源IPv4地址 */
		bucket = &table_v4[hsiphash_2u32(net_word, ip, &key) &
				   (table_size - 1)];                /* 计算IPv4哈希桶位置 */
	}
#if IS_ENABLED(CONFIG_IPV6)
	/* IPv6协议处理 */
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		/* Only use 64 bits, so as to ratelimit the whole /64.
		 * 
		 * IPv6设计决策：只使用IPv6地址的前64位进行速率限制。
		 * 这样可以对整个/64子网进行统一限制，符合IPv6网络分配惯例，
		 * 同时简化了算法实现和提升了性能。
		 */
		memcpy(&ip, &ipv6_hdr(skb)->saddr, sizeof(ip));   /* 复制IPv6地址前64位 */
		bucket = &table_v6[hsiphash_3u32(net_word, ip >> 32, ip, &key) &
				   (table_size - 1)];                /* 计算IPv6哈希桶位置 */
	}
#endif
	else
		return false;                                     /* 不支持的协议类型 */
		
	/* RCU临界区：无锁哈希表查找 */
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, bucket, hash) {
		if (entry->net == net && entry->ip == ip) {       /* 精确匹配网络命名空间和IP */
			u64 now, tokens;
			bool ret;
			/* Quasi-inspired by nft_limit.c, but this is actually a
			 * slightly different algorithm. Namely, we incorporate
			 * the burst as part of the maximum tokens, rather than
			 * as part of the rate.
			 * 
			 * 算法说明：受nft_limit.c启发但有所改进。
			 * 我们将突发能力作为最大令牌数的一部分，而不是速率的一部分。
			 * 这种设计更直观，计算更简单。
			 */
			spin_lock(&entry->lock);                      /* 保护条目更新的关键区域 */
			now = ktime_get_coarse_boottime_ns();         /* 获取当前时间 */
			
			/* 令牌桶更新：根据时间差线性增加令牌 */
			tokens = min_t(u64, TOKEN_MAX,                /* 令牌数不能超过桶容量 */
				       entry->tokens + now -             /* 当前令牌 + 时间差 */
					       entry->last_time_ns);     /* = 新的令牌数 */
			entry->last_time_ns = now;                    /* 更新最后访问时间 */
			
			/* 速率决策：检查是否有足够令牌 */
			ret = tokens >= PACKET_COST;                  /* 是否有足够令牌发送包 */
			entry->tokens = ret ? tokens - PACKET_COST : tokens;
			                                              /* 如果允许则扣除令牌，否则保持不变 */
			spin_unlock(&entry->lock);                    /* 释放条目锁 */
			rcu_read_unlock();                            /* 退出RCU临界区 */
			return ret;                                   /* 返回速率限制决策 */
		}
	}
	rcu_read_unlock();                                        /* 未找到条目，退出RCU临界区 */

	/* 未找到条目，需要创建新条目 */
	
	/* 内存保护：检查条目数量上限 */
	if (atomic_inc_return(&total_entries) > max_entries)
		goto err_oom;

	/* 从内存缓存池分配新条目 */
	entry = kmem_cache_alloc(entry_cache, GFP_KERNEL);
	if (unlikely(!entry))
		goto err_oom;

	/* 初始化新条目 */
	entry->net = net;                                         /* 设置网络命名空间 */
	entry->ip = ip;                                           /* 设置IP地址 */
	INIT_HLIST_NODE(&entry->hash);                           /* 初始化哈希节点 */
	spin_lock_init(&entry->lock);                            /* 初始化条目锁 */
	entry->last_time_ns = ktime_get_coarse_boottime_ns();     /* 设置创建时间 */
	entry->tokens = TOKEN_MAX - PACKET_COST;                 /* 初始令牌数（已扣除本次消耗） */
	
	/* 原子插入哈希表 */
	spin_lock(&table_lock);                                   /* 获取哈希表修改锁 */
	hlist_add_head_rcu(&entry->hash, bucket);                /* RCU安全插入 */
	spin_unlock(&table_lock);                                 /* 释放哈希表修改锁 */
	return true;                                              /* 新条目允许发送 */

err_oom:
	/* 内存不足或条目数超限处理 */
	atomic_dec(&total_entries);                               /* 回滚条目计数 */
	return false;                                             /* 拒绝发送 */
}

/*
 * ===================================================================
 * 速率限制器初始化函数
 * ===================================================================
 */

/**
 * wg_ratelimiter_init - 初始化速率限制器子系统
 * 
 * 返回值：成功时返回0，失败时返回负错误码
 * 
 * 功能描述：
 * 初始化全局速率限制器，包括内存缓存、哈希表分配、垃圾回收器启动等。
 * 支持多次调用（引用计数管理），系统级资源只初始化一次。
 * 
 * 初始化流程图：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                  速率限制器初始化流程                        │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  1. 引用计数管理                                            │
 * │     ├── 获取初始化互斥锁                                    │
 * │     ├── 检查引用计数                                        │
 * │     └── 如果已初始化则直接返回                              │
 * │                                                             │
 * │  2. 内存缓存池创建                                          │
 * │     ├── KMEM_CACHE(ratelimiter_entry)                      │
 * │     └── 优化频繁分配/释放性能                               │
 * │                                                             │
 * │  3. 哈希表大小计算                                          │
 * │     ├── 根据系统RAM动态计算                                 │
 * │     ├── 大内存系统: 8192桶                                  │
 * │     ├── 小内存系统: 16~计算值桶                             │
 * │     └── 最大条目数 = 桶数 × 8                               │
 * │                                                             │
 * │  4. 哈希表内存分配                                          │
 * │     ├── IPv4哈希表 (table_v4)                              │
 * │     ├── IPv6哈希表 (table_v6) [如果启用]                   │
 * │     └── 使用kvcalloc保证连续性                              │
 * │                                                             │
 * │  5. 系统组件启动                                            │
 * │     ├── 启动垃圾回收工作队列                                │
 * │     ├── 生成安全哈希密钥                                    │
 * │     └── 释放初始化锁                                        │
 * └─────────────────────────────────────────────────────────────┘
 * 
 * 动态哈希表大小计算：
 * ┌─────────────────────────────────────────────────────────────┐
 * │                   哈希表大小自适应算法                       │
 * ├─────────────────────────────────────────────────────────────┤
 * │                                                             │
 * │  系统内存分类：                                             │
 * │                                                             │
 * │  大内存系统 (>1GB RAM):                                     │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │  table_size = 8192 桶                               │   │
 * │  │  max_entries = 8192 × 8 = 65536 条目               │   │
 * │  │  内存占用 ≈ 8KB哈希表 + 1MB条目空间                │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │                                                             │
 * │  小内存系统 (≤1GB RAM):                                     │
 * │  ┌─────────────────────────────────────────────────────┐   │
 * │  │  计算公式:                                          │   │
 * │  │  ram_bytes = total_pages × page_size               │   │
 * │  │  table_size = ram_bytes ÷ 16KB ÷ sizeof(hlist)    │   │
 * │  │  table_size = max(16, round_up_pow2(计算值))       │   │
 * │  │                                                     │   │
 * │  │  示例 (512MB系统):                                 │   │
 * │  │  512MB ÷ 16KB ÷ 8字节 ≈ 4096桶                    │   │
 * │  │  max_entries = 4096 × 8 = 32768条目                │   │
 * │  └─────────────────────────────────────────────────────┘   │
 * │                                                             │
 * │  设计原理：                                                 │
 * │  • 内存占用与系统RAM成比例                                  │
 * │  • 2的幂大小优化哈希性能                                    │
 * │  • 最小16桶保证基本功能                                     │
 * │  • 8倍条目数提供良好的负载因子                              │
 * └─────────────────────────────────────────────────────────────┘
 */
int wg_ratelimiter_init(void)
{
	mutex_lock(&init_lock);
	if (++init_refcnt != 1)                                  /* 检查是否已初始化 */
		goto out;

	/* 创建条目专用内存缓存池 */
	entry_cache = KMEM_CACHE(ratelimiter_entry, 0);
	if (!entry_cache)
		goto err;

	/* xt_hashlimit.c uses a slightly different algorithm for ratelimiting,
	 * but what it shares in common is that it uses a massive hashtable. So,
	 * we borrow their wisdom about good table sizes on different systems
	 * dependent on RAM. This calculation here comes from there.
	 * 
	 * 哈希表大小计算：
	 * xt_hashlimit.c 使用了稍微不同的速率限制算法，但共同点是使用
	 * 大型哈希表。我们借鉴了它们关于不同系统RAM大小对应的合理
	 * 哈希表大小的智慧。这里的计算来源于该模块。
	 */
	table_size = (totalram_pages() > (1U << 30) / PAGE_SIZE) ? 8192 :
		max_t(unsigned long, 16, roundup_pow_of_two(
			(totalram_pages() << PAGE_SHIFT) /              /* 总内存字节数 */
			(1U << 14) / sizeof(struct hlist_head)));       /* 除以16KB再除以指针大小 */
	max_entries = table_size * 8;                             /* 最大条目数为桶数的8倍 */

	/* 分配IPv4哈希表内存 */
	table_v4 = kvcalloc(table_size, sizeof(*table_v4), GFP_KERNEL);
	if (unlikely(!table_v4))
		goto err_kmemcache;

#if IS_ENABLED(CONFIG_IPV6)
	/* 分配IPv6哈希表内存 (如果启用IPv6支持) */
	table_v6 = kvcalloc(table_size, sizeof(*table_v6), GFP_KERNEL);
	if (unlikely(!table_v6)) {
		kvfree(table_v4);                                /* 失败时清理已分配的IPv4表 */
		goto err_kmemcache;
	}
#endif

	/* 启动垃圾回收工作队列 - 1秒后首次执行 */
	queue_delayed_work(system_power_efficient_wq, &gc_work, HZ);
	
	/* 生成随机哈希密钥 - 防止哈希碰撞攻击 */
	get_random_bytes(&key, sizeof(key));
out:
	mutex_unlock(&init_lock);
	return 0;

err_kmemcache:
	kmem_cache_destroy(entry_cache);                          /* 清理内存缓存池 */
err:
	--init_refcnt;                                            /* 回滚引用计数 */
	mutex_unlock(&init_lock);
	return -ENOMEM;                                           /* 返回内存不足错误 */
}

void wg_ratelimiter_uninit(void)
{
	mutex_lock(&init_lock);
	if (!init_refcnt || --init_refcnt)
		goto out;

	cancel_delayed_work_sync(&gc_work);
	wg_ratelimiter_gc_entries(NULL);
	rcu_barrier();
	kvfree(table_v4);
#if IS_ENABLED(CONFIG_IPV6)
	kvfree(table_v6);
#endif
	kmem_cache_destroy(entry_cache);
out:
	mutex_unlock(&init_lock);
}

#include "selftest/ratelimiter.c"
