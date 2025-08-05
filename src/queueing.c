// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * queueing.c - WireGuard 包队列管理实现
 * 
 * 这个文件包含了 WireGuard 数据包队列管理的核心功能，主要用于：
 * 1. 管理多核心工作队列 (multicore worker queues)
 * 2. 实现加密队列 (crypt_queue) 的初始化和清理
 * 3. 实现无锁的前向队列 (prev_queue) 用于高性能包处理
 * 
 * WireGuard 使用这些队列来处理数据包的加密/解密操作，确保在多核系统上
 * 能够高效地并行处理网络数据包。
 */

#include "queueing.h"
#include <linux/skb_array.h>

/*
 * wg_packet_percpu_multicore_worker_alloc - 分配多核心工作队列
 * @function: 工作函数指针，将在工作队列中执行的函数
 * @ptr: 传递给工作函数的私有数据指针
 * 
 * 为每个 CPU 核心分配一个工作队列，用于并行处理数据包。
 * 这是 WireGuard 实现高性能的关键，允许在多核系统上同时处理多个数据包。
 * 
 * 返回值：成功时返回分配的多核心工作队列指针，失败时返回 NULL
 */
struct multicore_worker __percpu *
wg_packet_percpu_multicore_worker_alloc(work_func_t function, void *ptr)
{
	int cpu;
	/* 为每个 CPU 分配 multicore_worker 结构体 */
	struct multicore_worker __percpu *worker = alloc_percpu(struct multicore_worker);

	if (!worker)
		return NULL;

	/* 遍历系统中所有可能的 CPU 核心 */
	for_each_possible_cpu(cpu) {
		/* 设置每个 CPU 对应的工作队列的私有数据指针 */
		per_cpu_ptr(worker, cpu)->ptr = ptr;
		/* 初始化每个 CPU 对应的工作队列，绑定工作函数 */
		INIT_WORK(&per_cpu_ptr(worker, cpu)->work, function);
	}
	return worker;
}

/*
 * wg_packet_queue_init - 初始化加密队列
 * @queue: 要初始化的加密队列结构体指针
 * @function: 处理队列中数据包的工作函数
 * @len: 队列的最大长度
 * 
 * 初始化一个用于数据包加密/解密的队列。这个队列使用 ptr_ring 作为底层存储，
 * 并为每个 CPU 核心分配工作队列来并行处理数据包。
 * 
 * 返回值：成功时返回 0，失败时返回负错误码
 */
int wg_packet_queue_init(struct crypt_queue *queue, work_func_t function,
			 unsigned int len)
{
	int ret;

	/* 清零队列结构体 */
	memset(queue, 0, sizeof(*queue));
	
	/* 初始化底层的 ptr_ring，用于存储待处理的数据包指针 */
	ret = ptr_ring_init(&queue->ring, len, GFP_KERNEL);
	if (ret)
		return ret;
	
	/* 为这个队列分配多核心工作队列 */
	queue->worker = wg_packet_percpu_multicore_worker_alloc(function, queue);
	if (!queue->worker) {
		/* 分配失败时清理已初始化的 ptr_ring */
		ptr_ring_cleanup(&queue->ring, NULL);
		return -ENOMEM;
	}
	return 0;
}

/*
 * wg_packet_queue_free - 释放加密队列资源
 * @queue: 要释放的加密队列指针
 * @purge: 是否清除队列中剩余的数据包
 * 
 * 释放加密队列占用的所有资源，包括多核心工作队列和底层的 ptr_ring。
 * 如果 purge 为 true，会销毁队列中剩余的所有 sk_buff。
 */
void wg_packet_queue_free(struct crypt_queue *queue, bool purge)
{
	/* 释放所有 CPU 的工作队列 */
	free_percpu(queue->worker);
	
	/* 如果不清除队列但队列非空，发出警告 */
	WARN_ON(!purge && !__ptr_ring_empty(&queue->ring));
	
	/* 清理底层的 ptr_ring，如果 purge 为 true 则销毁剩余的 sk_buff */
	ptr_ring_cleanup(&queue->ring, purge ? __skb_array_destroy_skb : NULL);
}

/*
 * 无锁前向队列实现的宏定义
 * 
 * NEXT(skb): 利用 sk_buff 的 prev 字段作为单向链表的 next 指针
 * STUB(queue): 获取队列的哨兵节点，用于简化队列操作逻辑
 * 
 * 这种设计巧妙地重用了 sk_buff 结构体中的字段，避免了额外的内存分配
 */
#define NEXT(skb) ((skb)->prev)
#define STUB(queue) ((struct sk_buff *)&queue->empty)

/*
 * wg_prev_queue_init - 初始化前向队列
 * @queue: 要初始化的前向队列指针
 * 
 * 初始化一个无锁的单向队列，用于高性能的数据包缓存。
 * 这个队列实现了一个经典的无锁单向链表算法，支持多个生产者并发入队，
 * 但只支持单个消费者出队。
 */
void wg_prev_queue_init(struct prev_queue *queue)
{
	/* 初始化哨兵节点，其 next 指针为 NULL */
	NEXT(STUB(queue)) = NULL;
	
	/* 队列头尾都指向哨兵节点，表示空队列 */
	queue->head = queue->tail = STUB(queue);
	
	/* 初始化 peek 指针为 NULL */
	queue->peeked = NULL;
	
	/* 初始化队列计数器为 0 */
	atomic_set(&queue->count, 0);
	
	/*
	 * 编译时检查：确保 sk_buff 和 prev_queue.empty 的内存布局兼容
	 * 这个检查保证了我们可以安全地将 prev_queue.empty 当作 sk_buff 使用
	 */
	BUILD_BUG_ON(
		offsetof(struct sk_buff, next) != offsetof(struct prev_queue, empty.next) -
							offsetof(struct prev_queue, empty) ||
		offsetof(struct sk_buff, prev) != offsetof(struct prev_queue, empty.prev) -
							 offsetof(struct prev_queue, empty));
}

/*
 * __wg_prev_queue_enqueue - 内部入队函数（不检查队列长度）
 * @queue: 目标队列
 * @skb: 要入队的数据包
 * 
 * 这是无锁队列入队操作的核心实现。使用原子操作确保多个生产者
 * 可以并发安全地向队列中添加元素。
 */
static void __wg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb)
{
	/* 设置新节点的 next 指针为 NULL */
	WRITE_ONCE(NEXT(skb), NULL);
	
	/*
	 * 原子地更新队列头部：
	 * 1. 将 queue->head 设置为新的 skb
	 * 2. 返回原来的 head 值
	 * 3. 将原来的 head 的 next 指针指向新的 skb
	 * 
	 * 这个操作保证了即使多个线程同时入队，链表也能保持正确的结构
	 */
	WRITE_ONCE(NEXT(xchg_release(&queue->head, skb)), skb);
}

/*
 * wg_prev_queue_enqueue - 安全入队函数（带队列长度检查）
 * @queue: 目标队列
 * @skb: 要入队的数据包
 * 
 * 向队列中添加一个数据包，但会检查队列长度限制。
 * 如果队列已满（达到 MAX_QUEUED_PACKETS），则拒绝入队。
 * 
 * 返回值：成功入队返回 true，队列已满返回 false
 */
bool wg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb)
{
	/*
	 * 原子地增加队列计数，但不能超过 MAX_QUEUED_PACKETS
	 * 如果当前计数已经等于 MAX_QUEUED_PACKETS，则不增加计数并返回 false
	 */
	if (!atomic_add_unless(&queue->count, 1, MAX_QUEUED_PACKETS))
		return false;
	
	/* 执行实际的入队操作 */
	__wg_prev_queue_enqueue(queue, skb);
	return true;
}

/*
 * wg_prev_queue_dequeue - 从队列中取出一个数据包
 * @queue: 源队列
 * 
 * 从队列头部取出一个数据包。这个函数实现了无锁单向队列的出队操作，
 * 只能有一个消费者调用此函数。算法处理了各种边界情况，包括空队列、
 * 只有一个元素的队列等。
 * 
 * 返回值：成功时返回出队的 sk_buff 指针，队列为空时返回 NULL
 */
struct sk_buff *wg_prev_queue_dequeue(struct prev_queue *queue)
{
	/* 获取当前尾节点和其下一个节点 */
	struct sk_buff *tail = queue->tail, *next = smp_load_acquire(&NEXT(tail));

	/* 如果尾节点是哨兵节点 */
	if (tail == STUB(queue)) {
		/* 如果没有下一个节点，队列为空 */
		if (!next)
			return NULL;
		/* 移动尾指针到下一个节点，跳过哨兵节点 */
		queue->tail = next;
		tail = next;
		next = smp_load_acquire(&NEXT(next));
	}
	
	/* 如果有下一个节点，可以安全地出队当前尾节点 */
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		return tail;
	}
	if (tail != READ_ONCE(queue->head))
		return NULL;
	/*
	 * 队列可能只有一个元素，尝试插入哨兵节点来帮助后续操作
	 * 这是一个优化技巧，避免队列在只有一个元素时的竞态条件
	 */
	__wg_prev_queue_enqueue(queue, STUB(queue));
	next = smp_load_acquire(&NEXT(tail));
	
	/* 再次检查是否有下一个节点 */
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		return tail;
	}
	
	/* 队列确实为空 */
	return NULL;
}

/* 清理宏定义 */
#undef NEXT
#undef STUB
