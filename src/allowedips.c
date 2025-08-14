// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * allowedips.c - WireGuard 允许的 IP 地址路由表实现
 * 
 * 这个文件实现了 WireGuard 的核心路由功能，用于管理每个对等点(peer)允许访问的 IP 地址范围。
 * 它使用了一个高效的基数树(Radix Tree/Trie)数据结构来存储和查找 IP 地址前缀，
 * 支持 IPv4 和 IPv6 地址的快速最长前缀匹配。
 * 
 * 主要功能：
 * - IP 地址前缀的插入、删除和查找
 * - 支持 CIDR 表示法的网络地址
 * - RCU (Read-Copy-Update) 并发控制
 * - 内存高效的节点缓存管理
 * - 与 WireGuard 对等点的关联管理
 */

#include "allowedips.h"
#include "peer.h"

/* 节点内存缓存池，用于高效分配和释放 allowedips_node 结构体 */
static struct kmem_cache *node_cache;

/*
 * swap_endian - 字节序转换函数
 * @dst: 目标缓冲区
 * @src: 源数据（大端序）
 * @bits: 数据位数（32位用于IPv4，128位用于IPv6）
 * 
 * 将网络字节序（大端序）的IP地址转换为主机字节序，
 * 以便进行高效的位操作和比较。这对于在不同架构上
 * 保持一致的性能至关重要。
 */
static void swap_endian(u8 *dst, const u8 *src, u8 bits)
{
	/* 处理 IPv4 地址 (32位) */
	if (bits == 32) {
		/* 将32位大端序地址转换为主机字节序 */
		*(u32 *)dst = be32_to_cpu(*(const __be32 *)src);
	} else if (bits == 128) {
		/* 处理 IPv6 地址 (128位)，分两个64位段处理 */
		/* 转换前64位 */
		((u64 *)dst)[0] = be64_to_cpu(((const __be64 *)src)[0]);
		/* 转换后64位 */
		((u64 *)dst)[1] = be64_to_cpu(((const __be64 *)src)[1]);
	}
}

/*
 * copy_and_assign_cidr - 初始化节点的CIDR和位操作相关字段
 * @node: 要初始化的节点
 * @src: 源IP地址数据
 * @cidr: CIDR前缀长度（网络位数）
 * @bits: IP地址的总位数（IPv4为32，IPv6为128）
 * 
 * 该函数设置节点的CIDR值，并预计算出用于快速位操作的关键字段：
 * - bit_at_a: 要检查的字节位置索引
 * - bit_at_b: 该字节内的位位置
 * - bitlen: IP地址类型的位数
 * 这些预计算值使得后续的树遍历和前缀匹配非常高效。
 */
static void copy_and_assign_cidr(struct allowedips_node *node, const u8 *src,
				 u8 cidr, u8 bits)
{
	/* 设置节点的CIDR前缀长度 */
	node->cidr = cidr;
	
	/* 计算要检查的字节位置（cidr位所在的字节索引） */
	node->bit_at_a = cidr / 8U;
	
#ifdef __LITTLE_ENDIAN
	/* 在小端序系统上，需要调整字节位置以匹配字节序转换后的数据布局 */
	node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
	
	/* 计算在目标字节内的位位置（从高位开始计数） */
	node->bit_at_b = 7U - (cidr % 8U);
	
	/* 记录IP地址的位数（用于区分IPv4和IPv6） */
	node->bitlen = bits;
	
	/* 复制IP地址数据到节点中 */
	memcpy(node->bits, src, bits / 8U);
}

/*
 * choose - 根据关键字在指定位置的值选择子树方向
 * @node: 当前节点
 * @key: 要查找的IP地址键值
 * 
 * 返回值: 0或1，表示应该访问子节点bit[0]还是bit[1]
 * 
 * 这是基数树遍历的核心函数，通过检查关键字在特定位置的二进制位
 * 来决定该向左子树还是右子树方向遍历。
 */
static inline u8 choose(struct allowedips_node *node, const u8 *key)
{
	/* 提取关键字在指定位置的二进制位（0或1）
	 * key[node->bit_at_a]: 获取目标字节
	 * >> node->bit_at_b: 右移到目标位
	 * & 1: 只保留最低位（即目标位的值）
	 */
	return (key[node->bit_at_a] >> node->bit_at_b) & 1;
}

/*
 * push_rcu - 将RCU保护的节点指针推入堆栈
 * @stack: 节点指针堆栈数组
 * @p: RCU保护的节点指针
 * @len: 堆栈当前长度的指针
 * 
 * 该函数用于在树遍历过程中安全地将子节点添加到处理堆栈中。
 * 在RCU环境下，它确保只有非空节点才会被加入处理队列。
 */
static void push_rcu(struct allowedips_node **stack,
		     struct allowedips_node __rcu *p, unsigned int *len)
{
	/* 检查RCU指针是否非空 */
	if (rcu_access_pointer(p)) {
		/* Debug模式下检查堆栈溢出（最大深度128层） */
		WARN_ON(IS_ENABLED(DEBUG) && *len >= 128);
		/* 将节点指针推入堆栈并递增长度 */
		stack[(*len)++] = rcu_dereference_raw(p);
	}
}

/*
 * node_free_rcu - RCU延迟释放单个节点的回调函数
 * @rcu: RCU头结构，嵌入在allowedips_node中
 * 
 * 该函数在RCU宽限期过后被调用，安全地释放单个节点的内存。
 * 使用container_of宏从 RCU 头获取包含的allowedips_node结构体，
 * 然后将其返回到内存缓存池。
 */
static void node_free_rcu(struct rcu_head *rcu)
{
	/* 使用container_of从 RCU 头获取完整的节点结构体，并释放到缓存池 */
	kmem_cache_free(node_cache, container_of(rcu, struct allowedips_node, rcu));
}

/*
 * root_free_rcu - RCU延迟释放整个子树的回调函数
 * @rcu: RCU头结构，嵌入在根节点中
 * 
 * 该函数在RCU宽限期过后被调用，负责释放整个子树的所有节点。
 * 它使用一个堆栈来迭代地遍历树的所有节点，避免递归调用导致的
 * 栈溢出问题。这对于深度较大的树结构尤其重要。
 */
static void root_free_rcu(struct rcu_head *rcu)
{
	/* 初始化遍历堆栈，将根节点作为起始节点 */
	struct allowedips_node *node, *stack[128] = {
		container_of(rcu, struct allowedips_node, rcu) };
	unsigned int len = 1;

	/* 使用堆栈迭代遍历所有节点，避免递归调用 */
	while (len > 0 && (node = stack[--len])) {
		/* 将当前节点的左右子节点推入堆栈 */
		push_rcu(stack, node->bit[0], &len);
		push_rcu(stack, node->bit[1], &len);
		/* 释放当前节点的内存 */
		kmem_cache_free(node_cache, node);
	}
}

static void root_remove_peer_lists(struct allowedips_node *root)
{
	struct allowedips_node *node, *stack[128] = { root };
	unsigned int len = 1;

	while (len > 0 && (node = stack[--len])) {
		push_rcu(stack, node->bit[0], &len);
		push_rcu(stack, node->bit[1], &len);
		if (rcu_access_pointer(node->peer))
			list_del(&node->peer_list);
	}
}

/*
 * fls128 - 寻找128位数中最高位的位置
 * @a: 高64位
 * @b: 低64位
 * 
 * 返回值: 最高位1的位置（从1开始计数）
 * 
 * 这是一个用于128位数据的fls（find last set）操作的实现，
 * 主要用于 IPv6 地址的位操作和前缀匹配计算。
 */
static unsigned int fls128(u64 a, u64 b)
{
	/* 如果高64位非零，在高64位中找最高位并加上64 */
	/* 否则在低64位中直接找最高位 */
	return a ? fls64(a) + 64U : fls64(b);
}

/*
 * common_bits - 计算两个IP地址的公共前缀位数
 * @node: 节点，包含要比较的IP地址
 * @key: 要比较的另一个IP地址
 * @bits: IP地址的总位数（IPv4为32，IPv6为128）
 * 
 * 返回值: 公共前缀的位数
 * 
 * 该函数通过XOR操作计算两个地址的差异，然后使用fls操作
 * 找到最高位不同的位置，从而得出公共前缀的长度。
 * 这是基数树中判断节点包含关系的关键算法。
 */
static u8 common_bits(const struct allowedips_node *node, const u8 *key,
		      u8 bits)
{
	/* 处理IPv4地址（32位） */
	if (bits == 32)
		/* XOR操作找到不同位，然后用fls找最高不同位，最终计算公共位数 */
		return 32U - fls(*(const u32 *)node->bits ^ *(const u32 *)key);
	else if (bits == 128)
		/* 处理IPv6地址（128位），分别对高64位和低64位进行XOR操作 */
		return 128U - fls128(
			/* 高64位的XOR结果 */
			*(const u64 *)&node->bits[0] ^ *(const u64 *)&key[0],
			/* 低64位的XOR结果 */
			*(const u64 *)&node->bits[8] ^ *(const u64 *)&key[8]);
	/* 对于不支持的地址长度，返回0 */
	return 0;
}

/*
 * prefix_matches - 检查关键字是否与节点的前缀匹配
 * @node: 要检查的节点
 * @key: 要匹配的IP地址关键字
 * @bits: IP地址的总位数
 * 
 * 返回值: true 表示匹配，false 表示不匹配
 * 
 * 该函数通过比较公共前缀位数来判断关键字是否匹配节点的CIDR前缀。
 * 这是路由表查找的核心逻辑，决定是否继续在树中向下搜索。
 */
static bool prefix_matches(const struct allowedips_node *node, const u8 *key,
			   u8 bits)
{
	/* 注意：这里的实现在理论上可以更快（通过预计算掉码等方式），
	 * 但在现代处理器上，common_bits函数已经足够快了，
	 * 所以直接使用这种简洁的实现。
	 */
	
	/* 检查公共前缀位数是否大于等于节点的CIDR值 */
	return common_bits(node, key, bits) >= node->cidr;
}

/*
 * find_node - 在基数树中查找匹配指定IP地址的节点
 * @trie: 基数树的根节点
 * @bits: IP地址的位数
 * @key: 要查找的IP地址
 * 
 * 返回值: 找到的最优匹配节点，或NULL如果未找到
 * 
 * 这是IP路由表的核心查找算法，实现了最长前缀匹配（LPM）。
 * 它从根节点开始，沿着匹配的路径向下搜索，并跟踪最后一个
 * 具有关联对等点的节点作为结果返回。
 */
static struct allowedips_node *find_node(struct allowedips_node *trie, u8 bits,
					 const u8 *key)
{
	/* 初始化：从根节点开始，没有找到任何匹配 */
	struct allowedips_node *node = trie, *found = NULL;

	/* 沿着匹配的路径向下遍历 */
	while (node && prefix_matches(node, key, bits)) {
		/* 如果当前节点有关联的对等点，记录为匹配结果 */
		if (rcu_access_pointer(node->peer))
			found = node;
		
		/* 如果达到精确匹配（前缀长度等于IP位数），停止搜索 */
		if (node->cidr == bits)
			break;
		
		/* 根据关键字的下一个位选择子树方向 */
		node = rcu_dereference_bh(node->bit[choose(node, key)]);
	}
	
	/* 返回最后一个有效的匹配节点 */
	return found;
}

/*
 * lookup - 在允许IP表中查找匹配的对等点
 * @root: 基数树的根节点（RCU保护）
 * @bits: IP地址的位数（IPv4为32，IPv6为128）
 * @be_ip: 大端序的IP地址数据
 * 
 * 返回值: 对应的对等点的强引用，如果未找到则返回NULL
 * 
 * 这是数据包路由的核心函数，用于根据IP地址找到对应的WireGuard对等点。
 * 它使用最长前缀匹配算法，支持CIDR网络地址范围匹配。
 * 函数在RCU读取临界区内执行，确保并发安全性。
 * 
 * 注意：返回的是强引用，调用者需要在使用完毕后释放引用。
 */
static struct wg_peer *lookup(struct allowedips_node __rcu *root, u8 bits,
			      const void *be_ip)
{
	/* IP地址缓冲区，按64位对齐以便传递给fls/fls64函数 */
	u8 ip[16] __aligned(__alignof(u64));
	struct allowedips_node *node;
	struct wg_peer *peer = NULL;

	/* 将网络字节序的IP地址转换为主机字节序 */
	swap_endian(ip, be_ip, bits);

	/* 进入RCU读取临界区，禁止下半部中断 */
	rcu_read_lock_bh();
retry:
	/* 在基数树中查找匹配的节点 */
	node = find_node(rcu_dereference_bh(root), bits, ip);
	if (node) {
		/* 尝试获取对等点的引用，如果对等点仍然有效 */
		peer = wg_peer_get_maybe_zero(rcu_dereference_bh(node->peer));
		if (!peer)
			/* 对等点已被释放，重试查找（处理并发删除情况） */
			goto retry;
	}
	/* 退出RCU读取临界区 */
	rcu_read_unlock_bh();
	return peer;
}

/*
 * node_placement - 在基数树中找到新节点的插入位置
 * @trie: 基数树的根节点
 * @key: 要插入的IP地址关键字
 * @cidr: 要插入的CIDR前缀长度
 * @bits: IP地址的总位数
 * @rnode: 返回的父节点指针
 * @lock: 保护树结构的互斥锁
 * 
 * 返回值: true 表示找到精确匹配的节点，false 表示需要创建新节点
 * 
 * 该函数用于在插入操作中找到合适的插入位置。它从树根开始遍历，
 * 找到最深层的包含新节点的节点，或者找到精确匹配的现有节点。
 */
static bool node_placement(struct allowedips_node __rcu *trie, const u8 *key,
			   u8 cidr, u8 bits, struct allowedips_node **rnode,
			   struct mutex *lock)
{
	/* 在锁保护下获取根节点 */
	struct allowedips_node *node = rcu_dereference_protected(trie, lockdep_is_held(lock));
	struct allowedips_node *parent = NULL;
	bool exact = false;

	/* 沿着匹配路径向下遍历，直到找到合适的插入位置 */
	while (node && node->cidr <= cidr && prefix_matches(node, key, bits)) {
		parent = node;
		
		/* 如果找到CIDR值完全相同的节点，说明是精确匹配 */
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}
		
		/* 继续向下一级移动 */
		node = rcu_dereference_protected(parent->bit[choose(parent, key)], lockdep_is_held(lock));
	}
	
	/* 返回父节点位置 */
	*rnode = parent;
	return exact;
}

/*
 * connect_node - 将节点连接到指定的父节点位置
 * @parent: 父节点的子节点指针的地址
 * @bit: 该子节点在父节点中的位置索引（0或1）
 * @node: 要连接的子节点
 * 
 * 该函数建立父子节点之间的双向连接：
 * 1. 将父节点的子指针设置为新节点（使用RCU安全赋值）
 * 2. 在子节点中记录父节点信息（包括指针和位置）
 */
static inline void connect_node(struct allowedips_node __rcu **parent, u8 bit, struct allowedips_node *node)
{
	/* 将父节点指针地址和位置信息打包存储
	 * 低2位用于存储bit值，高位存储父节点指针地址 */
	node->parent_bit_packed = (unsigned long)parent | bit;
	
	/* 使用RCU安全赋值，将父节点的子指针设置为当前节点 */
	rcu_assign_pointer(*parent, node);
}

/*
 * choose_and_connect_node - 根据节点的IP地址选择合适的子树位置并连接
 * @parent: 父节点
 * @node: 要连接的子节点
 * 
 * 该函数是connect_node的便捷包装，它自动根据子节点的IP地址
 * 内容决定应该连接到父节点的哪个子树（bit[0]或bit[1]）。
 */
static inline void choose_and_connect_node(struct allowedips_node *parent, struct allowedips_node *node)
{
	/* 根据子节点的IP地址在父节点分割位置的值决定方向 */
	u8 bit = choose(parent, node->bits);
	
	/* 将子节点连接到相应的子树位置 */
	connect_node(&parent->bit[bit], bit, node);
}

/*
 * add - 在允许IP表中添加一个新的IP地址范围
 * @trie: 基数树根节点的指针的指针
 * @bits: IP地址的总位数（IPv4为32，IPv6为128）
 * @key: 要添加的IP地址（主机字节序）
 * @cidr: CIDR前缀长度
 * @peer: 关联的WireGuard对等点
 * @lock: 保护数据结构的互斥锁
 * 
 * 返回值: 0表示成功，负数表示错误码
 * 
 * 这是允许IP表的核心插入函数，实现了复杂的基数树插入逻辑。
 * 它处理多种情况：
 * 1. 空树：直接创建根节点
 * 2. 精确匹配：更新现有节点的对等点关联
 * 3. 部分匹配：需要分割或重组节点
 * 4. 完全不匹配：创建新的中间节点和叶子节点
 * 
 * 所有操作都是在互斥锁保护下进行的，确保并发安全性。
 */
static int add(struct allowedips_node __rcu **trie, u8 bits, const u8 *key,
	       u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	struct allowedips_node *node, *parent, *down, *newnode;

	/* 参数有效性检查：CIDR不能超过IP地址总位数，对等点不能为空 */
	if (unlikely(cidr > bits || !peer))
		return -EINVAL;

	/* 情况1：空树，创建第一个节点作为根节点 */
	if (!rcu_access_pointer(*trie)) {
		/* 从缓存池分配新节点并清零 */
		node = kmem_cache_zalloc(node_cache, GFP_KERNEL);
		if (unlikely(!node))
			return -ENOMEM;
		
		/* 初始化节点与对等点的关联 */
		RCU_INIT_POINTER(node->peer, peer);
		/* 将节点添加到对等点的允许IP列表中 */
		list_add_tail(&node->peer_list, &peer->allowedips_list);
		/* 设置节点的CIDR和IP地址信息 */
		copy_and_assign_cidr(node, key, cidr, bits);
		/* 将节点连接为树根，使用特殊值2表示根节点 */
		connect_node(trie, 2, node);
		return 0;
	}
	/* 情况2：检查是否存在精确匹配的节点 */
	if (node_placement(*trie, key, cidr, bits, &node, lock)) {
		/* 精确匹配：直接更新现有节点的对等点关联 */
		rcu_assign_pointer(node->peer, peer);
		/* 将节点移动到新对等点的允许IP列表末尾 */
		list_move_tail(&node->peer_list, &peer->allowedips_list);
		return 0;
	}

	/* 情况3/4：需要创建新节点，先分配并初始化新节点 */
	newnode = kmem_cache_zalloc(node_cache, GFP_KERNEL);
	if (unlikely(!newnode))
		return -ENOMEM;
	
	/* 初始化新节点的基本信息 */
	RCU_INIT_POINTER(newnode->peer, peer);
	list_add_tail(&newnode->peer_list, &peer->allowedips_list);
	copy_and_assign_cidr(newnode, key, cidr, bits);

	/* 确定需要处理的子树节点 */
	if (!node) {
		/* 没有包含节点，直接使用根节点 */
		down = rcu_dereference_protected(*trie, lockdep_is_held(lock));
	} else {
		/* 有包含节点，找到对应的子树 */
		const u8 bit = choose(node, key);
		down = rcu_dereference_protected(node->bit[bit], lockdep_is_held(lock));
		
		/* 如果子树为空，直接在此处连接新节点 */
		if (!down) {
			connect_node(&node->bit[bit], bit, newnode);
			return 0;
		}
	}
	/* 计算新节点和现有子树的共同前缀长度，决定分割点 */
	cidr = min(cidr, common_bits(down, key, bits));
	parent = node;

	/* 情况3：新节点的CIDR正好等于公共前缀长度 */
	if (newnode->cidr == cidr) {
		/* 新节点可以直接作为中间节点，将原有子树作为它的子节点 */
		choose_and_connect_node(newnode, down);
		
		/* 将新节点连接到其父节点 */
		if (!parent)
			/* 无父节点，作为新的根节点 */
			connect_node(trie, 2, newnode);
		else
			/* 连接到现有父节点 */
			choose_and_connect_node(parent, newnode);
		return 0;
	}

	/* 情况4：需要创建一个新的中间节点来容纳公共前缀 */
	node = kmem_cache_zalloc(node_cache, GFP_KERNEL);
	if (unlikely(!node)) {
		/* 分配失败，清理已创建的新节点 */
		list_del(&newnode->peer_list);
		kmem_cache_free(node_cache, newnode);
		return -ENOMEM;
	}
	
	/* 初始化中间节点（不关联对等点，只用于路由） */
	INIT_LIST_HEAD(&node->peer_list);
	copy_and_assign_cidr(node, newnode->bits, cidr, bits);

	/* 将原有子树和新节点都连接到中间节点 */
	choose_and_connect_node(node, down);
	choose_and_connect_node(node, newnode);
	
	/* 将中间节点连接到树中的合适位置 */
	if (!parent)
		/* 作为新的根节点 */
		connect_node(trie, 2, node);
	else
		/* 连接到现有父节点 */
		choose_and_connect_node(parent, node);
	
	return 0;
}

/*
 * wg_allowedips_init - 初始化允许IP表结构
 * @table: 要初始化的允许IP表
 * 
 * 初始化一个空的允许IP表，将IPv4和IPv6的根节点设置为NULL，
 * 并将序列号初始化为1。序列号用于跟踪表的修改操作。
 */
void wg_allowedips_init(struct allowedips *table)
{
	/* 初始化IPv4和IPv6的树根为空 */
	table->root4 = table->root6 = NULL;
	/* 初始化序列号，用于跟踪表的修改操作 */
	table->seq = 1;
}

/*
 * wg_allowedips_free - 释放允许IP表的所有资源
 * @table: 要释放的允许IP表
 * @lock: 保护表结构的互斥锁
 * 
 * 该函数完全清空允许IP表，释放所有相关的内存和数据结构。
 * 操作包括：
 * 1. 递增序列号以标记表的更改
 * 2. 清空IPv4和IPv6树的根指针
 * 3. 清理所有节点与对等点的关联
 * 4. 使用RCU延迟释放所有节点内存
 * 
 * 所有操作都在互斥锁保护下进行，确保并发安全性。
 */
void wg_allowedips_free(struct allowedips *table, struct mutex *lock)
{
	struct allowedips_node __rcu *old4 = table->root4, *old6 = table->root6;

	++table->seq;
	RCU_INIT_POINTER(table->root4, NULL);
	RCU_INIT_POINTER(table->root6, NULL);
	if (rcu_access_pointer(old4)) {
		struct allowedips_node *node = rcu_dereference_protected(old4,
							lockdep_is_held(lock));

		root_remove_peer_lists(node);
		call_rcu(&node->rcu, root_free_rcu);
	}
	if (rcu_access_pointer(old6)) {
		struct allowedips_node *node = rcu_dereference_protected(old6,
							lockdep_is_held(lock));

		root_remove_peer_lists(node);
		call_rcu(&node->rcu, root_free_rcu);
	}
}

/*
 * wg_allowedips_insert_v4 - 在允许IP表中插入IPv4地址范围
 * @table: 允许IP表
 * @ip: IPv4地址（网络字节序）
 * @cidr: CIDR前缀长度（0-32）
 * @peer: 关联的WireGuard对等点
 * @lock: 保护表结构的互斥锁
 * 
 * 返回值: 0表示成功，负数表示错误码
 * 
 * 将一个IPv4地址范围添加到允许IP表中，关联到指定的对等点。
 * 这允许该对等点发送和接收来自该地址范围的数据包。
 */
int wg_allowedips_insert_v4(struct allowedips *table, const struct in_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* IPv4地址缓冲区，按32位对齐以便传递给fls函数 */
	u8 key[4] __aligned(__alignof(u32));

	/* 递增序列号，标记表的修改 */
	++table->seq;
	/* 将IPv4地址从网络字节序转换为主机字节序 */
	swap_endian(key, (const u8 *)ip, 32);
	/* 调用核心添加函数，在IPv4树中插入节点 */
	return add(&table->root4, 32, key, cidr, peer, lock);
}

/*
 * wg_allowedips_insert_v6 - 在允许IP表中插入IPv6地址范围
 * @table: 允许IP表
 * @ip: IPv6地址（网络字节序）
 * @cidr: CIDR前缀长度（0-128）
 * @peer: 关联的WireGuard对等点
 * @lock: 保护表结构的互斥锁
 * 
 * 返回值: 0表示成功，负数表示错误码
 * 
 * 将一个IPv6地址范围添加到允许IP表中，关联到指定的对等点。
 * 这允许该对等点发送和接收来自该地址范围的数据包。
 */
int wg_allowedips_insert_v6(struct allowedips *table, const struct in6_addr *ip,
			    u8 cidr, struct wg_peer *peer, struct mutex *lock)
{
	/* IPv6地址缓冲区，按64位对齐以便传递给fls64函数 */
	u8 key[16] __aligned(__alignof(u64));

	/* 递增序列号，标记表的修改 */
	++table->seq;
	/* 将IPv6地址从网络字节序转换为主机字节序 */
	swap_endian(key, (const u8 *)ip, 128);
	/* 调用核心添加函数，在IPv6树中插入节点 */
	return add(&table->root6, 128, key, cidr, peer, lock);
}

void wg_allowedips_remove_by_peer(struct allowedips *table,
				  struct wg_peer *peer, struct mutex *lock)
{
	struct allowedips_node *node, *child, **parent_bit, *parent, *tmp;
	bool free_parent;

	if (list_empty(&peer->allowedips_list))
		return;
	++table->seq;
	list_for_each_entry_safe(node, tmp, &peer->allowedips_list, peer_list) {
		list_del_init(&node->peer_list);
		RCU_INIT_POINTER(node->peer, NULL);
		if (node->bit[0] && node->bit[1])
			continue;
		child = rcu_dereference_protected(node->bit[!rcu_access_pointer(node->bit[0])],
						  lockdep_is_held(lock));
		if (child)
			child->parent_bit_packed = node->parent_bit_packed;
		parent_bit = (struct allowedips_node **)(node->parent_bit_packed & ~3UL);
		*parent_bit = child;
		parent = (void *)parent_bit -
			 offsetof(struct allowedips_node, bit[node->parent_bit_packed & 1]);
		free_parent = !rcu_access_pointer(node->bit[0]) &&
			      !rcu_access_pointer(node->bit[1]) &&
			      (node->parent_bit_packed & 3) <= 1 &&
			      !rcu_access_pointer(parent->peer);
		if (free_parent)
			child = rcu_dereference_protected(
					parent->bit[!(node->parent_bit_packed & 1)],
					lockdep_is_held(lock));
		call_rcu(&node->rcu, node_free_rcu);
		if (!free_parent)
			continue;
		if (child)
			child->parent_bit_packed = parent->parent_bit_packed;
		*(struct allowedips_node **)(parent->parent_bit_packed & ~3UL) = child;
		call_rcu(&parent->rcu, node_free_rcu);
	}
}

/*
 * wg_allowedips_read_node - 从节点中读取IP地址和CIDR信息
 * @node: 要读取的节点
 * @ip: 输出IP地址的缓冲区（最多16字节）
 * @cidr: 输出CIDR前缀长度
 * 
 * 返回值: AF_INET 表示IPv4，AF_INET6 表示IPv6
 * 
 * 从允许IP表节点中提取IP地址和CIDR信息，将其转换为网络字节序
 * 并正确处理CIDR授码位。该函数通常用于配置显示和调试。
 */
int wg_allowedips_read_node(struct allowedips_node *node, u8 ip[16], u8 *cidr)
{
	/* 计算CIDR前缀需要的字节数（向上取整） */
	const unsigned int cidr_bytes = DIV_ROUND_UP(node->cidr, 8U);
	
	/* 将节点中的IP地址从主机字节序转换为网络字节序 */
	swap_endian(ip, node->bits, node->bitlen);
	
	/* 清零CIDR前缀之外的所有字节 */
	memset(ip + cidr_bytes, 0, node->bitlen / 8U - cidr_bytes);
	
	/* 如果CIDR不是8的整数倍，需要清零最后一个字节的未使用位 */
	if (node->cidr)
		/* 使用掉码清零未使用的低位 */
		ip[cidr_bytes - 1U] &= ~0U << (-node->cidr % 8U);

	/* 输出CIDR值 */
	*cidr = node->cidr;
	/* 根据位数返回地址族类型 */
	return node->bitlen == 32 ? AF_INET : AF_INET6;
}

/*
 * wg_allowedips_lookup_dst - 根据数据包的目标地址查找对等点
 * @table: 允许IP表
 * @skb: 网络数据包
 * 
 * 返回值: 对应的对等点的强引用，如果未找到则返回NULL
 * 
 * 该函数用于发送数据包时的路由决策。它检查数据包的目标IP地址，
 * 并在允许IP表中查找匹配的对等点。这确保了数据包只会被路由到
 * 允许访问该目标地址的对等点。
 * 
 * 注意：返回的是强引用，调用者需要在使用完毕后释放引用。
 */
struct wg_peer *wg_allowedips_lookup_dst(struct allowedips *table,
					 struct sk_buff *skb)
{
	/* 根据数据包的协议类型判断IP版本 */
	if (skb->protocol == htons(ETH_P_IP))
		/* IPv4数据包：在IPv4树中查找目标地址 */
		return lookup(table->root4, 32, &ip_hdr(skb)->daddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		/* IPv6数据包：在IPv6树中查找目标地址 */
		return lookup(table->root6, 128, &ipv6_hdr(skb)->daddr);
	/* 不支持的协议类型 */
	return NULL;
}

/*
 * wg_allowedips_lookup_src - 根据数据包的源地址查找对等点
 * @table: 允许IP表
 * @skb: 网络数据包
 * 
 * 返回值: 对应的对等点的强引用，如果未找到则返回NULL
 * 
 * 该函数用于接收数据包时的源地址验证。它检查数据包的源IP地址，
 * 并在允许IP表中查找匹配的对等点。这确保了只有来自允许地址范围的
 * 数据包才会被接受和处理，提供了重要的安全防护。
 * 
 * 注意：返回的是强引用，调用者需要在使用完毕后释放引用。
 */
struct wg_peer *wg_allowedips_lookup_src(struct allowedips *table,
					 struct sk_buff *skb)
{
	/* 根据数据包的协议类型判断IP版本 */
	if (skb->protocol == htons(ETH_P_IP))
		/* IPv4数据包：在IPv4树中查找源地址 */
		return lookup(table->root4, 32, &ip_hdr(skb)->saddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		/* IPv6数据包：在IPv6树中查找源地址 */
		return lookup(table->root6, 128, &ipv6_hdr(skb)->saddr);
	/* 不支持的协议类型 */
	return NULL;
}

/*
 * wg_allowedips_slab_init - 初始化允许IP表的内存缓存池
 * 
 * 返回值: 0表示成功，-ENOMEM表示内存不足
 * 
 * 在模块初始化时调用，为allowedips_node结构体创建专用的内存缓存池。
 * 使用缓存池能够显著提高内存分配和释放的效率，特别是在高频的
 * 节点创建和销毁场景下。
 */
int __init wg_allowedips_slab_init(void)
{
	/* 为allowedips_node结构体创建专用的内存缓存池 */
	node_cache = KMEM_CACHE(allowedips_node, 0);
	/* 返回创建结果：成功返回0，失败返回-ENOMEM */
	return node_cache ? 0 : -ENOMEM;
}

/*
 * wg_allowedips_slab_uninit - 清理允许IP表的内存缓存池
 * 
 * 在模块卸载时调用，清理之前创建的内存缓存池。
 * 首先等待所有RCU回调完成，确保没有未完成的内存释放操作，
 * 然后销毁缓存池。这确保了模块卸载的安全性。
 */
void wg_allowedips_slab_uninit(void)
{
	/* 等待所有正在进行的RCU回调完成 */
	rcu_barrier();
	/* 销毁内存缓存池 */
	kmem_cache_destroy(node_cache);
}

#include "selftest/allowedips.c"
