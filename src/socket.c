// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                           WireGuard 网络套接字管理模块                       ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  此模块负责WireGuard的UDP套接字管理和网络数据包的发送接收                    ║
 * ║                                                                              ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐    ║
 * ║  │                        网络架构图                                   │    ║
 * ║  │                                                                     │    ║
 * ║  │  应用层数据 ──→ [WireGuard封装] ──→ UDP套接字 ──→ IP层             │    ║
 * ║  │       ↓                ↓               ↓           ↓                │    ║
 * ║  │  ┌─────────┐   ┌─────────────┐   ┌──────────┐  ┌──────────┐        │    ║
 * ║  │  │用户数据 │───│ 加密+认证   │───│UDP隧道   │──│路由选择  │        │    ║
 * ║  │  │(明文)   │   │(WG协议)     │   │(socket)  │  │(IPv4/6)  │        │    ║
 * ║  │  └─────────┘   └─────────────┘   └──────────┘  └──────────┘        │    ║
 * ║  │                                       ↓                            │    ║
 * ║  │                                  ┌──────────┐                      │    ║
 * ║  │                                  │网络接口  │                      │    ║
 * ║  │                                  │(物理网卡)│                      │    ║
 * ║  │                                  └──────────┘                      │    ║
 * ║  └─────────────────────────────────────────────────────────────────────┘    ║
 * ║                                                                              ║
 * ║  核心功能：                                                                  ║
 * ║  ┌──────────────────────────────────────────────────────────────────────┐   ║
 * ║  │ • IPv4/IPv6双栈支持 - 同时支持两种IP协议                             │   ║
 * ║  │ • UDP隧道封装 - 使用UDP协议承载WireGuard数据包                       │   ║
 * ║  │ • 路径优化 - 缓存路由信息减少查找开销                               │   ║
 * ║  │ • 端点管理 - 动态学习和更新对等节点的网络地址                       │   ║
 * ║  │ • NAT穿透支持 - 处理网络地址转换环境下的连通性                      │   ║
 * ║  │ • 源地址验证 - 确保数据包来源的合法性                               │   ║
 * ║  └──────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                              ║
 * ║  数据流向：                                                                  ║
 * ║  发送：WireGuard设备 → UDP套接字 → 网络栈 → 物理网络                       ║
 * ║  接收：物理网络 → 网络栈 → UDP套接字 → WireGuard设备                       ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"

#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <net/udp_tunnel.h>
#include <net/ipv6.h>

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                            IPv4 UDP数据包发送函数                            ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  通过IPv4 UDP套接字发送WireGuard数据包到指定的端点                           ║
 * ║                                                                              ║
 * ║  数据包发送流程：                                                            ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                     IPv4发送处理流程                               │     ║
 * ║  │                                                                    │     ║
 * ║  │  输入SKB → 设置数据包属性 → 获取UDP套接字                          │     ║
 * ║  │     ↓              ↓              ↓                               │     ║
 * ║  │ ┌─────────┐  ┌─────────────┐  ┌──────────┐                        │     ║
 * ║  │ │数据包   │  │设备标记     │  │RCU保护   │                        │     ║
 * ║  │ │属性设置 │  │防火墙标记   │  │的套接字  │                        │     ║
 * ║  │ └─────────┘  └─────────────┘  └──────────┘                        │     ║
 * ║  │     ↓                              ↓                              │     ║
 * ║  │ 构造流信息(flowi4) → 查找路由表 → 缓存路由 → UDP隧道发送            │     ║
 * ║  │     ↓              ↓         ↓        ↓                           │     ║
 * ║  │ ┌─────────┐  ┌─────────────┐ ┌──────────┐ ┌──────────────┐       │     ║
 * ║  │ │源/目标  │  │安全策略     │ │目标缓存  │ │UDP封装并发送 │       │     ║
 * ║  │ │地址端口 │  │分类检查     │ │优化查找  │ │到网络接口    │       │     ║
 * ║  │ └─────────┘  └─────────────┘ └──────────┘ └──────────────┘       │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  参数说明：                                                                  ║
 * ║  • wg - WireGuard设备实例                                                    ║
 * ║  • skb - 要发送的数据包缓冲区                                                ║
 * ║  • endpoint - 目标端点信息(IP地址、端口等)                                   ║
 * ║  • ds - DSCP (Differentiated Services) 标记                                 ║
 * ║  • cache - 目标缓存，用于优化路由查找                                        ║
 * ║                                                                              ║
 * ║  返回值：0表示成功，负数表示错误码                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
static int send4(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
	// 构造IPv4流信息结构，用于路由查找
	struct flowi4 fl = {
		.saddr = endpoint->src4.s_addr,             // 源IP地址
		.daddr = endpoint->addr4.sin_addr.s_addr,   // 目标IP地址
		.fl4_dport = endpoint->addr4.sin_port,      // 目标UDP端口
		.flowi4_mark = wg->fwmark,                  // 防火墙标记
		.flowi4_proto = IPPROTO_UDP                 // 协议类型: UDP
	};
	struct rtable *rt = NULL;                       // 路由表项
	struct sock *sock;                              // UDP套接字
	int ret = 0;                                    // 返回值

	// 设置数据包基本属性
	skb_mark_not_on_list(skb);                      // 标记数据包不在链表中
	skb->dev = wg->dev;                             // 设置发送设备
	skb->mark = wg->fwmark;                         // 设置数据包防火墙标记

	// 使用RCU锁保护套接字访问
	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock4);           // 获取IPv4套接字

	if (unlikely(!sock)) {                          // 套接字不存在
		ret = -ENONET;                          // 网络不可达错误
		goto err;
	}

	fl.fl4_sport = inet_sk(sock)->inet_sport;       // 设置源UDP端口

	// 尝试从缓存获取路由信息
	if (cache)
		rt = dst_cache_get_ip4(cache, &fl.saddr);

	if (!rt) {                                      // 缓存中没有路由信息
		// 进行安全策略分类检查
		security_sk_classify_flow(sock, flowi4_to_flowi(&fl));
		
		// 验证源地址是否有效
		if (unlikely(!inet_confirm_addr(sock_net(sock), NULL, 0,
						fl.saddr, RT_SCOPE_HOST))) {
			// 源地址无效，清零相关信息
			endpoint->src4.s_addr = 0;          // 清除源IP
			endpoint->src_if4 = 0;              // 清除源接口
			fl.saddr = 0;                       // 清除流中的源地址
			if (cache)
				dst_cache_reset(cache);     // 重置目标缓存
		}
		
		// 查找到目标的路由
		rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		
		// 检查源接口是否匹配
		if (unlikely(endpoint->src_if4 && ((IS_ERR(rt) &&
			     PTR_ERR(rt) == -EINVAL) || (!IS_ERR(rt) &&
			     rt->dst.dev->ifindex != endpoint->src_if4)))) {
			// 接口不匹配，清除源信息并重新查找路由
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
			if (!IS_ERR(rt))
				ip_rt_put(rt);              // 释放路由引用
			rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		}
		
		if (IS_ERR(rt)) {                           // 路由查找失败
			ret = PTR_ERR(rt);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		
		// 将路由信息保存到缓存
		if (cache)
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
	}

	// 设置数据包忽略DF (Don't Fragment) 标志
	skb->ignore_df = 1;
	
	// 通过UDP隧道发送数据包
	udp_tunnel_xmit_skb(rt, sock, skb, fl.saddr, fl.daddr, ds,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false, false);
	goto out;

err:
	kfree_skb(skb);                                 // 错误时释放数据包
out:
	rcu_read_unlock_bh();                           // 释放RCU锁
	return ret;
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                            IPv6 UDP数据包发送函数                            ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  通过IPv6 UDP套接字发送WireGuard数据包到指定的端点                           ║
 * ║                                                                              ║
 * ║  IPv6发送流程：                                                              ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                     IPv6发送处理流程                               │     ║
 * ║  │                                                                    │     ║
 * ║  │  输入SKB → IPv6配置检查 → 构造流信息(flowi6)                       │     ║
 * ║  │     ↓            ↓              ↓                                  │     ║
 * ║  │ ┌─────────┐ ┌─────────────┐ ┌──────────────┐                       │     ║
 * ║  │ │数据包   │ │编译时IPv6   │ │源/目标IPv6   │                       │     ║
 * ║  │ │属性设置 │ │支持检查     │ │地址+端口     │                       │     ║
 * ║  │ └─────────┘ └─────────────┘ └──────────────┘                       │     ║
 * ║  │     ↓                              ↓                              │     ║
 * ║  │ 获取IPv6套接字 → IPv6路由查找 → 缓存优化 → UDP6隧道发送            │     ║
 * ║  │     ↓              ↓           ↓          ↓                        │     ║
 * ║  │ ┌─────────┐  ┌─────────────┐ ┌──────────┐ ┌──────────────┐        │     ║
 * ║  │ │RCU保护  │  │IPv6地址     │ │目标缓存  │ │IPv6 UDP封装  │        │     ║
 * ║  │ │套接字   │  │有效性验证   │ │性能优化  │ │并发送到接口  │        │     ║
 * ║  │ └─────────┘  └─────────────┘ └──────────┘ └──────────────┘        │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  IPv6特有特性：                                                              ║
 * ║  ┌──────────────────────────────────────────────────────────────────────┐   ║
 * ║  │ • 128位IPv6地址处理                                                  │   ║
 * ║  │ • 作用域ID (scope_id) 支持 - 链路本地地址                           │   ║
 * ║  │ • IPv6流标签支持 (TODO: sin6_flowinfo)                              │   ║
 * ║  │ • 地址类型检查 (单播/多播/链路本地等)                               │   ║
 * ║  │ • IPv6专用的跳数限制 (hop limit)                                    │   ║
 * ║  └──────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                              ║
 * ║  编译时支持：只有在CONFIG_IPV6启用时才编译IPv6代码                           ║
 * ║                                                                              ║
 * ║  参数与返回值同IPv4版本                                                      ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
static int send6(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
#if IS_ENABLED(CONFIG_IPV6)                           // IPv6支持编译检查
	// 构造IPv6流信息结构，用于路由查找
	struct flowi6 fl = {
		.saddr = endpoint->src6,                    // 源IPv6地址
		.daddr = endpoint->addr6.sin6_addr,         // 目标IPv6地址
		.fl6_dport = endpoint->addr6.sin6_port,     // 目标UDP端口
		.flowi6_mark = wg->fwmark,                  // 防火墙标记
		.flowi6_oif = endpoint->addr6.sin6_scope_id,// 输出接口(作用域ID)
		.flowi6_proto = IPPROTO_UDP                 // 协议类型: UDP
		/* TODO: addr->sin6_flowinfo */            // IPv6流标签(待实现)
	};
	struct dst_entry *dst = NULL;                   // IPv6目标入口
	struct sock *sock;                              // UDP套接字
	int ret = 0;                                    // 返回值

	// 设置数据包基本属性
	skb_mark_not_on_list(skb);                      // 标记数据包不在链表中
	skb->dev = wg->dev;                             // 设置发送设备
	skb->mark = wg->fwmark;                         // 设置数据包防火墙标记

	// 使用RCU锁保护套接字访问
	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock6);           // 获取IPv6套接字

	if (unlikely(!sock)) {                          // IPv6套接字不存在
		ret = -ENONET;                          // 网络不可达错误
		goto err;
	}

	fl.fl6_sport = inet_sk(sock)->inet_sport;       // 设置源UDP端口

	// 尝试从缓存获取IPv6路由信息
	if (cache)
		dst = dst_cache_get_ip6(cache, &fl.saddr);

	if (!dst) {                                     // 缓存中没有路由信息
		// 进行安全策略分类检查
		security_sk_classify_flow(sock, flowi6_to_flowi(&fl));
		
		// 验证IPv6源地址是否有效
		if (unlikely(!ipv6_addr_any(&fl.saddr) &&
			     !ipv6_chk_addr(sock_net(sock), &fl.saddr, NULL, 0))) {
			// 源地址无效，使用任意地址(::)
			endpoint->src6 = fl.saddr = in6addr_any;
			if (cache)
				dst_cache_reset(cache);     // 重置目标缓存
		}
		
		// 通过IPv6子系统查找路由
		dst = ipv6_stub->ipv6_dst_lookup_flow(sock_net(sock), sock, &fl,
						      NULL);
		if (IS_ERR(dst)) {                          // IPv6路由查找失败
			ret = PTR_ERR(dst);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		
		// 将IPv6路由信息保存到缓存
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	// 设置数据包忽略DF (Don't Fragment) 标志
	skb->ignore_df = 1;
	
	// 通过IPv6 UDP隧道发送数据包
	udp_tunnel6_xmit_skb(dst, sock, skb, skb->dev, &fl.saddr, &fl.daddr, ds,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport, false);
	goto out;

err:
	kfree_skb(skb);                                 // 错误时释放数据包
out:
	rcu_read_unlock_bh();                           // 释放RCU锁
	return ret;
#else
	// IPv6未编译支持，直接释放数据包并返回不支持错误
	kfree_skb(skb);
	return -EAFNOSUPPORT;                           // 地址族不支持
#endif
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                         向对等节点发送SKB数据包                              ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  这是WireGuard发送数据包的主要入口函数，根据端点类型选择发送方法             ║
 * ║                                                                              ║
 * ║  发送决策流程：                                                              ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                      数据包发送决策树                             │     ║
 * ║  │                                                                    │     ║
 * ║  │  输入SKB → 获取端点锁 → 检查地址族类型                             │     ║
 * ║  │     ↓          ↓           ↓                                       │     ║
 * ║  │ ┌─────────┐ ┌─────────┐ ┌─────────────┐                            │     ║
 * ║  │ │记录包   │ │读锁保护 │ │AF_INET?     │ ──→ 调用send4()            │     ║
 * ║  │ │长度     │ │端点信息 │ │AF_INET6?    │ ──→ 调用send6()            │     ║
 * ║  │ └─────────┘ └─────────┘ │其他?        │ ──→ 释放SKB                │     ║
 * ║  │                        └─────────────┘                            │     ║
 * ║  │                               ↓                                   │     ║
 * ║  │                        发送成功? → 统计tx_bytes                   │     ║
 * ║  │                               ↓                                   │     ║
 * ║  │                        释放端点锁 → 返回结果                      │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  统计功能：                                                                  ║
 * ║  • 成功发送时累计peer->tx_bytes发送字节统计                                  ║
 * ║  • 失败时不更新统计，由调用者处理错误                                        ║
 * ║                                                                              ║
 * ║  线程安全：使用读锁保护端点信息，允许并发读取但防止写入冲突                  ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • peer - 目标对等节点                                                       ║
 * ║  • skb - 要发送的数据包缓冲区                                                ║
 * ║  • ds - DSCP流量类型标记                                                     ║
 * ║                                                                              ║
 * ║  返回值：0表示成功，负数表示错误码                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds)
{
	size_t skb_len = skb->len;                          // 记录数据包长度用于统计
	int ret = -EAFNOSUPPORT;                            // 默认返回地址族不支持

	read_lock_bh(&peer->endpoint_lock);                 // 获取端点读锁保护端点信息
	
	// 根据端点地址族类型选择相应的发送函数
	if (peer->endpoint.addr.sa_family == AF_INET)       // IPv4地址族
	// aw: peer->endpoint 是目标地址信息
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache);
	else if (peer->endpoint.addr.sa_family == AF_INET6) // IPv6地址族
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache);
	else                                                // 未知或不支持的地址族
		dev_kfree_skb(skb);                         // 直接释放数据包
	
	// 发送成功时更新发送字节统计
	if (likely(!ret))
		peer->tx_bytes += skb_len;              // 累计发送字节数
	
	read_unlock_bh(&peer->endpoint_lock);               // 释放端点读锁

	return ret;
}

/*
 * ┌──────────────────────────────────────────────────────────────────────────────┐
 * │                        向对等节点发送缓冲区数据                              │
 * │                                                                              │
 * │  将内存缓冲区中的数据封装成SKB数据包后发送给对等节点                          │
 * │                                                                              │
 * │  处理流程：                                                                  │
 * │  ┌────────────────────────────────────────────────────────────────────┐     │
 * │  │ 内存缓冲区 → 分配SKB → 预留头部空间 → 复制数据 → 发送SKB           │     │
 * │  │     ↓           ↓           ↓            ↓         ↓               │     │
 * │  │ ┌─────────┐ ┌─────────┐ ┌─────────────┐ ┌──────┐ ┌─────────────┐   │     │
 * │  │ │用户      │ │原子分配 │ │预留协议头部 │ │数据  │ │调用SKB发送  │   │     │
 * │  │ │提供数据   │ │SKB内存  │ │空间(header) │ │复制  │ │函数处理     │   │     │
 * │  │ └─────────┘ └─────────┘ └─────────────┘ └──────┘ └─────────────┘   │     │
 * │  └────────────────────────────────────────────────────────────────────┘     │
 * │                                                                              │
 * │  内存管理：                                                                  │
 * │  • GFP_ATOMIC分配 - 可在中断/软中断上下文中使用                              │
 * │  • SKB_HEADER_LEN预留 - 为各层协议头部预留空间                              │
 * │  • 失败时自动释放资源，无需调用者处理                                        │
 * │                                                                              │
 * │  使用场景：                                                                  │
 * │  • 发送握手消息                                                              │
 * │  • 发送控制消息                                                              │
 * │  • 发送已在内存中准备好的数据                                                │
 * │                                                                              │
 * │  参数：                                                                      │
 * │  • peer - 目标对等节点                                                       │
 * │  • buffer - 要发送的数据缓冲区指针                                           │
 * │  • len - 数据长度                                                            │
 * │  • ds - DSCP流量标记                                                         │
 * │                                                                              │
 * │  返回值：0表示成功，-ENOMEM表示内存不足，其他负值表示发送错误                │
 * └──────────────────────────────────────────────────────────────────────────────┘
 */
int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *buffer,
				  size_t len, u8 ds)
{
	// 分配SKB，额外分配头部空间用于协议封装
	struct sk_buff *skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);

	if (unlikely(!skb))                                 // 内存分配失败
		return -ENOMEM;

	skb_reserve(skb, SKB_HEADER_LEN);                   // 预留协议头部空间
	skb_set_inner_network_header(skb, 0);               // 设置内层网络头部偏移
	skb_put_data(skb, buffer, len);                     // 将缓冲区数据复制到SKB
	
	// 调用SKB发送函数完成实际发送
	return wg_socket_send_skb_to_peer(peer, skb, ds);
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                       作为对收到数据包的回复发送缓冲区                       ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  从接收到的数据包中提取源地址信息，然后向该地址发送回复数据                  ║
 * ║  主要用于握手消息的回复和其他需要向数据包来源回复的场景                      ║
 * ║                                                                              ║
 * ║  回复处理流程：                                                              ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                      数据包回复处理流程                           │     ║
 * ║  │                                                                    │     ║
 * ║  │  接收SKB → 提取端点信息 → 分配回复SKB → 复制回复数据               │     ║
 * ║  │     ↓            ↓              ↓            ↓                     │     ║
 * ║  │ ┌─────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │     ║
 * ║  │ │输入数据 │ │源IP/端口    │ │内存分配     │ │数据准备     │       │     ║
 * ║  │ │包验证   │ │提取和验证   │ │SKB缓冲区    │ │复制到SKB    │       │     ║
 * ║  │ └─────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │     ║
 * ║  │     ↓                                         ↓                   │     ║
 * ║  │ 地址族判断 → IPv4发送(send4) 或 IPv6发送(send6)                   │     ║
 * ║  │     ↓              ↓                 ↓                             │     ║
 * ║  │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                   │     ║
 * ║  │ │AF_INET      │ │无目标缓存   │ │AF_INET6     │                   │     ║
 * ║  │ │IPv4回复     │ │直接发送     │ │IPv6回复     │                   │     ║
 * ║  │ └─────────────┘ └─────────────┘ └─────────────┘                   │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  应用场景：                                                                  ║
 * ║  ┌──────────────────────────────────────────────────────────────────────┐   ║
 * ║  │ • 握手初始化的响应消息                                               │   ║
 * ║  │ • 握手响应的确认消息                                                 │   ║
 * ║  │ • 错误消息的回复                                                     │   ║
 * ║  │ • 其他需要向数据包来源发送回复的场景                                 │   ║
 * ║  └──────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                              ║
 * ║  注意：不使用目标缓存，因为这通常是一次性回复                                ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • wg - WireGuard设备实例                                                    ║
 * ║  • in_skb - 接收到的原始数据包，从中提取目标地址                             ║
 * ║  • buffer - 要发送的回复数据缓冲区                                           ║
 * ║  • len - 回复数据长度                                                        ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb, void *buffer,
					  size_t len)
{
	int ret = 0;
	struct sk_buff *skb;
	struct endpoint endpoint;

	if (unlikely(!in_skb))                              // 输入SKB无效
		return -EINVAL;
	
	// 从接收到的数据包中提取端点信息(源地址变成目标地址)
	ret = wg_socket_endpoint_from_skb(&endpoint, in_skb);
	if (unlikely(ret < 0))                              // 端点信息提取失败
		return ret;

	// 为回复数据分配SKB
	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))                                 // 内存分配失败
		return -ENOMEM;
	
	skb_reserve(skb, SKB_HEADER_LEN);                   // 预留协议头部空间
	skb_set_inner_network_header(skb, 0);               // 设置内层网络头部
	skb_put_data(skb, buffer, len);                     // 复制回复数据到SKB

	// 根据地址族选择发送函数，注意：不使用缓存，因为这是一次性回复
	if (endpoint.addr.sa_family == AF_INET)             // IPv4回复
		ret = send4(wg, skb, &endpoint, 0, NULL);
	else if (endpoint.addr.sa_family == AF_INET6)       // IPv6回复
		ret = send6(wg, skb, &endpoint, 0, NULL);
	/* 如果端点有效（上面已检查），则不会有其他可能性 */

	return ret;
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                        从SKB数据包提取端点信息函数                           ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  从接收到的网络数据包中解析并提取源地址信息，构造端点结构                    ║
 * ║  用于确定数据包的来源，以便后续通信或回复                                    ║
 * ║                                                                              ║
 * ║  解析流程：                                                                  ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                      数据包解析处理流程                           │     ║
 * ║  │                                                                    │     ║
 * ║  │  输入SKB → 协议类型检查 → IPv4/IPv6分支处理                        │     ║
 * ║  │     ↓            ↓              ↓                                  │     ║
 * ║  │ ┌─────────┐ ┌─────────────┐ ┌──────────────────┐                   │     ║
 * ║  │ │清空端点 │ │检查以太网   │ │ETH_P_IP?         │ ──→ IPv4处理       │     ║
 * ║  │ │结构体   │ │协议字段     │ │ETH_P_IPV6?       │ ──→ IPv6处理       │     ║
 * ║  │ └─────────┘ └─────────────┘ │其他?             │ ──→ 返回错误       │     ║
 * ║  │                            └──────────────────┘                   │     ║
 * ║  │                                    ↓                              │     ║
 * ║  │ IPv4分支: 提取源IP、源端口、目标IP、入接口                          │     ║
 * ║  │ IPv6分支: 提取源IPv6、源端口、目标IPv6、作用域ID                    │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  提取的信息：                                                                ║
 * ║  ┌──────────────────────────────────────────────────────────────────────┐   ║
 * ║  │ IPv4端点：                                                           │   ║
 * ║  │ • addr4 - 源IPv4地址和端口 (对方的地址)                             │   ║
 * ║  │ • src4 - 目标IPv4地址 (本地地址)                                    │   ║
 * ║  │ • src_if4 - 接收接口索引                                            │   ║
 * ║  │                                                                      │   ║
 * ║  │ IPv6端点：                                                           │   ║
 * ║  │ • addr6 - 源IPv6地址和端口 (对方的地址)                             │   ║
 * ║  │ • src6 - 目标IPv6地址 (本地地址)                                    │   ║
 * ║  │ • sin6_scope_id - IPv6作用域ID (链路本地地址使用)                   │   ║
 * ║  └──────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                              ║
 * ║  地址转换：源地址变成目标地址，用于回复通信                                  ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • endpoint - 输出的端点信息结构                                             ║
 * ║  • skb - 要解析的网络数据包                                                  ║
 * ║                                                                              ║
 * ║  返回值：0表示成功，-EINVAL表示不支持的协议类型                              ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
int wg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb)
{
	memset(endpoint, 0, sizeof(*endpoint));             // 清空端点结构体
	
	// 根据以太网协议类型进行分支处理
	if (skb->protocol == htons(ETH_P_IP)) {             // IPv4数据包
		endpoint->addr4.sin_family = AF_INET;       // 设置地址族
		endpoint->addr4.sin_port = udp_hdr(skb)->source;    // 源UDP端口
		endpoint->addr4.sin_addr.s_addr = ip_hdr(skb)->saddr; // 源IPv4地址
		endpoint->src4.s_addr = ip_hdr(skb)->daddr;     // 目标IPv4地址(本地)
		endpoint->src_if4 = skb->skb_iif;               // 接收接口索引
	} else if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6)) { // IPv6数据包
		endpoint->addr6.sin6_family = AF_INET6;         // 设置IPv6地址族
		endpoint->addr6.sin6_port = udp_hdr(skb)->source;   // 源UDP端口
		endpoint->addr6.sin6_addr = ipv6_hdr(skb)->saddr;   // 源IPv6地址
		// 计算IPv6作用域ID（对链路本地地址重要）
		endpoint->addr6.sin6_scope_id = ipv6_iface_scope_id(
			&ipv6_hdr(skb)->saddr, skb->skb_iif);
		endpoint->src6 = ipv6_hdr(skb)->daddr;          // 目标IPv6地址(本地)
	} else {                                            // 不支持的协议类型
		return -EINVAL;
	}
	return 0;
}

/*
 * ┌──────────────────────────────────────────────────────────────────────────────┐
 * │                              端点比较函数                                    │
 * │                                                                              │
 * │  比较两个端点结构是否相等，支持IPv4和IPv6两种地址族                          │
 * │                                                                              │
 * │  比较逻辑：                                                                  │
 * │  ┌────────────────────────────────────────────────────────────────────┐     │
 * │  │ 地址族相同? → IPv4比较 或 IPv6比较 或 特殊情况处理                 │     │
 * │  │     ↓              ↓           ↓              ↓                   │     │
 * │  │ ┌─────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │     │
 * │  │ │检查地址 │ │IPv4全字段   │ │IPv6全字段   │ │两端点都为   │       │     │
 * │  │ │族类型   │ │精确比较     │ │精确比较     │ │未初始化状态 │       │     │
 * │  │ └─────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │     │
 * │  └────────────────────────────────────────────────────────────────────┘     │
 * │                                                                              │
 * │  IPv4比较字段：                                                              │
 * │  • sin_port - UDP端口号                                                      │
 * │  • sin_addr.s_addr - IPv4地址                                               │
 * │  • src4.s_addr - 源IPv4地址                                                 │
 * │  • src_if4 - 源接口索引                                                      │
 * │                                                                              │
 * │  IPv6比较字段：                                                              │
 * │  • sin6_port - UDP端口号                                                     │
 * │  • sin6_addr - IPv6地址 (使用ipv6_addr_equal比较)                           │
 * │  • sin6_scope_id - 作用域ID                                                  │
 * │  • src6 - 源IPv6地址                                                         │
 * │                                                                              │
 * │  特殊情况：两个端点都未初始化(sa_family为0)时也视为相等                      │
 * │                                                                              │
 * │  用途：避免不必要的端点更新，优化网络性能                                    │
 * │                                                                              │
 * │  参数：a, b - 要比较的两个端点指针                                           │
 * │  返回值：true表示相等，false表示不等                                         │
 * └──────────────────────────────────────────────────────────────────────────────┘
 */
static bool endpoint_eq(const struct endpoint *a, const struct endpoint *b)
{
	// IPv4端点比较
	return (a->addr.sa_family == AF_INET && b->addr.sa_family == AF_INET &&
		a->addr4.sin_port == b->addr4.sin_port &&               // 端口相等
		a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr &&  // IPv4地址相等
		a->src4.s_addr == b->src4.s_addr && a->src_if4 == b->src_if4) || // 源信息相等
	       // IPv6端点比较
	       (a->addr.sa_family == AF_INET6 &&
		b->addr.sa_family == AF_INET6 &&
		a->addr6.sin6_port == b->addr6.sin6_port &&              // 端口相等
		ipv6_addr_equal(&a->addr6.sin6_addr, &b->addr6.sin6_addr) && // IPv6地址相等
		a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&      // 作用域ID相等
		ipv6_addr_equal(&a->src6, &b->src6)) ||                  // 源IPv6相等
	       // 特殊情况：两个端点都未初始化
	       unlikely(!a->addr.sa_family && !b->addr.sa_family);
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                           设置对等节点端点信息                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  更新对等节点的网络端点信息，用于后续的数据包发送                            ║
 * ║  实现了优化的写锁机制和目标缓存管理                                          ║
 * ║                                                                              ║
 * ║  更新流程：                                                                  ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                      端点更新优化流程                             │     ║
 * ║  │                                                                    │     ║
 * ║  │  新端点 → 无锁比较 → 相同?退出 → 获取写锁 → 地址族判断            │     ║
 * ║  │     ↓          ↓         ↓           ↓          ↓                 │     ║
 * ║  │ ┌─────────┐ ┌────────┐ ┌──────┐ ┌─────────┐ ┌─────────────┐       │     ║
 * ║  │ │输入端点 │ │快速比较│ │性能  │ │写锁保护 │ │IPv4/IPv6    │       │     ║
 * ║  │ │信息     │ │现有端点│ │优化  │ │写操作   │ │分支处理     │       │     ║
 * ║  │ └─────────┘ └────────┘ └──────┘ └─────────┘ └─────────────┘       │     ║
 * ║  │                                      ↓                           │     ║
 * ║  │              复制端点数据 → 重置目标缓存 → 释放写锁                │     ║
 * ║  │                    ↓              ↓           ↓                   │     ║
 * ║  │            ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │     ║
 * ║  │            │更新地址信息 │ │清除路由缓存 │ │解锁并退出   │        │     ║
 * ║  │            │和接口信息   │ │强制重新查找 │ │             │        │     ║
 * ║  │            └─────────────┘ └─────────────┘ └─────────────┘        │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  性能优化特性：                                                              ║
 * ║  ┌──────────────────────────────────────────────────────────────────────┐   ║
 * ║  │ • 无锁快速比较 - 端点变化很少见，先无锁检查避免不必要的锁开销        │   ║
 * ║  │ • 竞态条件容忍 - 即使多CPU同时写入相同内容也不会造成问题           │   ║
 * ║  │ • 写锁保护 - 确保端点更新的原子性                                   │   ║
 * ║  │ • 自动缓存管理 - 端点改变时自动重置路由缓存                         │   ║
 * ║  └──────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                              ║
 * ║  使用场景：                                                                  ║
 * ║  • 从接收的数据包学习对等节点的新地址                                        ║
 * ║  • 处理NAT环境下的地址变化                                                   ║
 * ║  • 用户配置更新                                                              ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • peer - 要更新的对等节点                                                   ║
 * ║  • endpoint - 新的端点信息                                                   ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint)
{
	/* 首先进行无锁检查以优化性能，因为端点变化很少见
	 * 如果正好在写入过程中，两个CPU写入相同或略不同的内容
	 * 也不会造成太大问题
	 */
	if (endpoint_eq(endpoint, &peer->endpoint))         // 端点相同，无需更新
		return;
		
	write_lock_bh(&peer->endpoint_lock);                // 获取写锁保护端点修改
	
	// 根据地址族类型更新相应的端点信息
	if (endpoint->addr.sa_family == AF_INET) {          // IPv4端点
		peer->endpoint.addr4 = endpoint->addr4;     // 复制IPv4地址和端口
		peer->endpoint.src4 = endpoint->src4;       // 复制源IPv4地址
		peer->endpoint.src_if4 = endpoint->src_if4; // 复制源接口索引
	} else if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6) { // IPv6端点
		peer->endpoint.addr6 = endpoint->addr6;     // 复制IPv6地址和端口
		peer->endpoint.src6 = endpoint->src6;       // 复制源IPv6地址
	} else {                                            // 不支持的地址族
		goto out;                                   // 直接退出，不更新
	}
	
	// 端点改变时重置目标缓存，强制重新进行路由查找
	dst_cache_reset(&peer->endpoint_cache);
	
out:
	write_unlock_bh(&peer->endpoint_lock);              // 释放写锁
}

/*
 * ┌──────────────────────────────────────────────────────────────────────────────┐
 * │                    从SKB数据包设置对等节点端点                              │
 * │                                                                              │
 * │  从接收到的数据包中提取端点信息并更新对等节点的端点配置                      │
 * │  这是端点学习机制的核心，实现动态的地址发现                                  │
 * │                                                                              │
 * │  处理流程：                                                                  │
 * │  ┌────────────────────────────────────────────────────────────────────┐     │
 * │  │ 接收SKB → 提取端点信息 → 验证成功? → 更新节点端点                  │     │
 * │  │    ↓           ↓             ↓           ↓                          │     │
 * │  │ ┌────────┐ ┌─────────────┐ ┌──────┐ ┌─────────────────┐              │     │
 * │  │ │网络数据│ │解析IP/端口  │ │成功？│ │调用端点更新函数 │              │     │
 * │  │ │包输入  │ │地址信息     │ │      │ │进行实际更新     │              │     │
 * │  │ └────────┘ └─────────────┘ └──────┘ └─────────────────┘              │     │
 * │  └────────────────────────────────────────────────────────────────────┘     │
 * │                                                                              │
 * │  应用场景：                                                                  │
 * │  • 接收握手消息时学习对方真实地址                                            │
 * │  • NAT穿透后的地址更新                                                       │
 * │  • 移动网络环境下的地址变化适应                                              │
 * │                                                                              │
 * │  错误处理：提取端点失败时静默忽略，不更新端点                                │
 * │                                                                              │
 * │  参数：                                                                      │
 * │  • peer - 要更新端点的对等节点                                               │
 * │  • skb - 包含地址信息的网络数据包                                            │
 * └──────────────────────────────────────────────────────────────────────────────┘
 */
void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb)
{
	struct endpoint endpoint;

	// 从SKB提取端点信息，成功时更新对等节点端点
	if (!wg_socket_endpoint_from_skb(&endpoint, skb))
		wg_socket_set_peer_endpoint(peer, &endpoint);
}

/*
 * ┌──────────────────────────────────────────────────────────────────────────────┐
 * │                        清除对等节点端点源地址                               │
 * │                                                                              │
 * │  清除对等节点端点的源地址信息，强制重新进行路由查找                          │
 * │  主要用于网络环境变化时重置连接状态                                          │
 * │                                                                              │
 * │  清除操作：                                                                  │
 * │  ┌────────────────────────────────────────────────────────────────────┐     │
 * │  │ 获取写锁 → 清零源地址 → 立即重置缓存 → 释放写锁                    │     │
 * │  │    ↓           ↓            ↓             ↓                        │     │
 * │  │ ┌────────┐ ┌─────────────┐ ┌──────────────┐ ┌──────────┐           │     │
 * │  │ │写锁保护│ │memset清零   │ │强制缓存重置  │ │解锁退出  │           │     │
 * │  │ │并发安全│ │src6字段     │ │立即生效      │ │          │           │     │
 * │  │ └────────┘ └─────────────┘ └──────────────┘ └──────────┘           │     │
 * │  └────────────────────────────────────────────────────────────────────┘     │
 * │                                                                              │
 * │  使用场景：                                                                  │
 * │  • 握手重传前清理旧的源地址信息                                              │
 * │  • 网络接口变化时重置路由缓存                                                │
 * │  • NAT映射过期时清除可能无效的源地址                                         │
 * │  • 定时器超时时的连接状态重置                                                │
 * │                                                                              │
 * │  注意：只清除IPv6源地址，IPv4源地址通过其他机制处理                         │
 * │                                                                              │
 * │  参数：peer - 要清除源地址的对等节点                                         │
 * └──────────────────────────────────────────────────────────────────────────────┘
 */
void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer)
{
	write_lock_bh(&peer->endpoint_lock);                // 获取写锁保护
	memset(&peer->endpoint.src6, 0, sizeof(peer->endpoint.src6)); // 清零IPv6源地址
	dst_cache_reset_now(&peer->endpoint_cache);         // 立即重置目标缓存
	write_unlock_bh(&peer->endpoint_lock);              // 释放写锁
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                           UDP数据包接收回调函数-非常重要的回调函数！                             ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  这是UDP套接字的接收回调函数，当收到WireGuard数据包时被内核调用              ║
 * ║  将接收到的原始UDP数据包转发给WireGuard包处理系统                            ║
 * ║                                                                              ║
 * ║  接收流程：                                                                  ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │ 内核UDP栈 → 套接字回调 → 验证套接字 → 获取设备 → WG包处理           │     ║
 * ║  │     ↓           ↓           ↓           ↓           ↓               │     ║
 * ║  │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐     │     ║
 * ║  │ │UDP数据包│ │sk非空？ │ │设备指针 │ │标记SKB  │ │调用WG包     │     │     ║
 * ║  │ │到达     │ │验证     │ │有效？   │ │不在链表 │ │处理函数     │     │     ║
 * ║  │ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────┘     │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  错误处理：任何验证失败都会释放SKB并返回0（成功）                            ║
 * ║  返回0告诉内核我们已经处理了这个包，避免进一步处理                          ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • sk - UDP套接字指针                                                        ║
 * ║  • skb - 接收到的网络数据包缓冲区                                            ║
 * ║                                                                              ║
 * ║  返回值：总是返回0，表示包已被处理                                           ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
static int wg_receive(struct sock *sk, struct sk_buff *skb)
{
	struct wg_device *wg;

	if (unlikely(!sk))                              // 套接字指针无效
		goto err;
	wg = sk->sk_user_data;                          // 从套接字获取WG设备指针
	if (unlikely(!wg))                              // WG设备指针无效
		goto err;
	skb_mark_not_on_list(skb);                      // 标记SKB不在任何链表中
	wg_packet_receive(wg, skb);                     // 将包交给WG包处理系统
	return 0;

err:
	kfree_skb(skb);                                 // 错误时释放数据包
	return 0;                                       // 总是返回0表示已处理
}

static void sock_free(struct sock *sock)
{
	if (unlikely(!sock))
		return;
	sk_clear_memalloc(sock);
	udp_tunnel_sock_release(sock->sk_socket);
}

static void set_sock_opts(struct socket *sock)
{
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                           WireGuard套接字初始化函数                          ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  为WireGuard设备创建和配置UDP套接字，支持IPv4和IPv6双栈                      ║
 * ║  这是WireGuard网络通信的基础设施初始化                                       ║
 * ║                                                                              ║
 * ║  初始化流程：                                                                ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                    套接字初始化处理流程                           │     ║
 * ║  │                                                                    │     ║
 * ║  │ 获取网络命名空间 → 创建IPv4套接字 → 配置套接字选项                  │     ║
 * ║  │         ↓                ↓              ↓                         │     ║
 * ║  │ ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐            │     ║
 * ║  │ │RCU保护的       │ │UDP套接字    │ │内存分配策略     │            │     ║
 * ║  │ │creating_net    │ │绑定端口     │ │发送缓冲区设置   │            │     ║
 * ║  │ └─────────────────┘ └─────────────┘ └─────────────────┘            │     ║
 * ║  │         ↓                                                          │     ║
 * ║  │ 设置UDP隧道 → 创建IPv6套接字(可选) → 最终套接字配置                 │     ║
 * ║  │         ↓              ↓                    ↓                     │     ║
 * ║  │ ┌─────────────┐ ┌─────────────────┐ ┌─────────────────────┐       │     ║
 * ║  │ │回调函数     │ │相同端口重用     │ │调用wg_socket_reinit │       │     ║
 * ║  │ │设置         │ │端口冲突重试     │ │完成设备配置         │       │     ║
 * ║  │ └─────────────┘ └─────────────────┘ └─────────────────────┘       │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  特殊处理：                                                                  ║
 * ║  • IPv6端口冲突时最多重试100次                                               ║
 * ║  • IPv4和IPv6套接字使用相同端口                                              ║
 * ║  • 套接字配置针对高性能网络传输优化                                          ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
int wg_socket_init(struct wg_device *wg, u16 port)
{
	struct net *net;
	int ret;
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_receive // 设置UDP接受回调
	};
	struct socket *new4 = NULL, *new6 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(port),
		.use_udp_checksums = true
	};
#if IS_ENABLED(CONFIG_IPV6)
	int retries = 0;
	struct udp_port_cfg port6 = {
		.family = AF_INET6,
		.local_ip6 = IN6ADDR_ANY_INIT,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
		.ipv6_v6only = true
	};
#endif

	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net))
		return -ENONET;

#if IS_ENABLED(CONFIG_IPV6)
retry:
#endif

	ret = udp_sock_create(net, &port4, &new4);// 创建UDP监听（端口51820）
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 socket\n", wg->dev->name);
		goto out;
	}
	set_sock_opts(new4);
	setup_udp_tunnel_sock(net, new4, &cfg);

#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6_mod_enabled()) {
		port6.local_udp_port = inet_sk(new4->sk)->inet_sport;
		ret = udp_sock_create(net, &port6, &new6);
		if (ret < 0) {
			udp_tunnel_sock_release(new4);
			if (ret == -EADDRINUSE && !port && retries++ < 100)
				goto retry;
			pr_err("%s: Could not create IPv6 socket\n",
			       wg->dev->name);
			goto out;
		}
		set_sock_opts(new6);
		setup_udp_tunnel_sock(net, new6, &cfg);
	}
#endif

	wg_socket_reinit(wg, new4->sk, new6 ? new6->sk : NULL);
	ret = 0;
out:
	put_net(net);
	return ret;
}

/*
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                          WireGuard套接字重新初始化                          ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                              ║
 * ║  安全地更新WireGuard设备的套接字，确保无缝的套接字切换                       ║
 * ║  使用RCU机制保证并发安全性和无锁读取性能                                     ║
 * ║                                                                              ║
 * ║  更新流程：                                                                  ║
 * ║  ┌────────────────────────────────────────────────────────────────────┐     ║
 * ║  │                      安全套接字更新流程                           │     ║
 * ║  │                                                                    │     ║
 * ║  │ 获取更新锁 → 保存旧套接字 → RCU指针更新 → 更新端口信息              │     ║
 * ║  │     ↓            ↓             ↓             ↓                     │     ║
 * ║  │ ┌─────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │     ║
 * ║  │ │互斥锁   │ │RCU保护的    │ │原子指针     │ │记录新监听   │        │     ║
 * ║  │ │保护     │ │指针获取     │ │赋值操作     │ │端口号       │        │     ║
 * ║  │ └─────────┘ └─────────────┘ └─────────────┘ └─────────────┘        │     ║
 * ║  │     ↓                                         ↓                   │     ║
 * ║  │ 释放更新锁 → 网络同步等待 → 安全释放旧套接字                        │     ║
 * ║  │     ↓            ↓             ↓                                   │     ║
 * ║  │ ┌─────────┐ ┌─────────────┐ ┌─────────────────┐                    │     ║
 * ║  │ │允许新的 │ │确保所有CPU  │ │释放旧套接字资源 │                    │     ║
 * ║  │ │并发访问 │ │看到新指针   │ │防止内存泄漏     │                    │     ║
 * ║  │ └─────────┘ └─────────────┘ └─────────────────┘                    │     ║
 * ║  └────────────────────────────────────────────────────────────────────┘     ║
 * ║                                                                              ║
 * ║  RCU安全机制：                                                               ║
 * ║  • rcu_assign_pointer - 原子地更新RCU保护的指针                             ║
 * ║  • synchronize_net - 等待所有网络RCU读取完成                                ║
 * ║  • 确保没有代码还在使用旧套接字时才释放                                      ║
 * ║                                                                              ║
 * ║  参数：                                                                      ║
 * ║  • wg - WireGuard设备实例                                                    ║
 * ║  • new4/new6 - 新的IPv4/IPv6套接字(可为NULL)                                ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
void wg_socket_reinit(struct wg_device *wg, struct sock *new4,
		      struct sock *new6)
{
	struct sock *old4, *old6;

	mutex_lock(&wg->socket_update_lock);            // 获取套接字更新互斥锁
	
	// 在锁保护下安全地获取当前套接字指针
	old4 = rcu_dereference_protected(wg->sock4,
				lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6,
				lockdep_is_held(&wg->socket_update_lock));
	
	// RCU原子指针更新，确保读取者看到一致状态
	rcu_assign_pointer(wg->sock4, new4);
	rcu_assign_pointer(wg->sock6, new6);
	
	// 更新设备的监听端口信息
	if (new4)
		wg->incoming_port = ntohs(inet_sk(new4)->inet_sport);
	
	mutex_unlock(&wg->socket_update_lock);          // 释放互斥锁
	
	// 等待所有网络RCU读取操作完成
	synchronize_net();
	
	// 安全地释放旧套接字资源
	sock_free(old4);
	sock_free(old6);
}
