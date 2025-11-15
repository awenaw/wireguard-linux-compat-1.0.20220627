// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/*
 * WIREGUARD 设备管理核心:
 *
 * 这是 WireGuard 网络设备的核心管理代码，实现了 Linux 网络设备接口
 * 并管理 WireGuard 虚拟网络设备的完整生命周期。
 *
 * 核心功能:
 * 1. 网络设备操作 (netdev_ops)
 *    - wg_open()  - 设备启动，初始化 socket 和 peer 连接
 *    - wg_stop()  - 设备关闭，清理所有连接和密钥
 *    - wg_xmit()  - 数据包传输，实现 cryptokey routing
 *
 * 2. 设备生命周期管理
 *    - wg_newlink() - 创建新的 WireGuard 设备实例
 *    - wg_destruct() - 设备销毁，释放所有资源
 *    - wg_setup() - 设备初始化配置
 *
 * 3. 系统集成
 *    - 电源管理 (PM) 通知处理
 *    - 网络命名空间 (netns) 支持
 *    - RTNL 链路操作集成
 *
 * 4. 工作队列管理
 *    - handshake_receive_wq - 握手接收处理
 *    - handshake_send_wq - 握手发送处理  
 *    - packet_crypt_wq - 数据包加密/解密
 *
 * 数据流转:
 * 发送: 应用层 -> wg_xmit() -> allowedips查找 -> 分组加密 -> UDP发送
 * 接收: UDP接收 -> 解密验证 -> 路由检查 -> 转发到应用层
 */

#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/dst_metadata.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>

static LIST_HEAD(device_list); /* 全局设备列表，用于系统级操作 */

/* 
 * 网络设备启动函数 - 当 'ip link set wg0 up' 时调用
 * 初始化 UDP socket，发送缓存的数据包，启动 keepalive
 * aw:他注册到了下面的netdev_ops函数表中
 */
static int wg_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	int ret;

	/* 禁用 IPv4 重定向，防止泄露内部路由信息 */
	if (dev_v4) {
		/* 在隧道环境中，ICMP 重定向可能暴露内部网络拓扑
		 * 因此禁用发送重定向消息
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
	/* 禁用 IPv6 自动地址生成，WireGuard 使用静态配置 */
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	if (dev_v6)
#ifndef COMPAT_CANNOT_USE_DEV_CNF
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	/* 设备更新锁保护关键操作 */
	mutex_lock(&wg->device_update_lock);
	
	/* 初始化 UDP socket 监听指定端口 */
	ret = wg_socket_init(wg, wg->incoming_port);
	if (ret < 0)
		goto out;
	
	/* 为所有已配置的 peer 发送缓存的数据包和 keepalive */
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		/* 发送在设备关闭期间缓存的数据包 */
		wg_packet_send_staged_packets(peer);
		/* 如果配置了持久 keepalive，立即发送一个 */
		if (peer->persistent_keepalive_interval)
			wg_packet_send_keepalive(peer);
	}
out:
	mutex_unlock(&wg->device_update_lock);
	return ret;
}

#ifdef CONFIG_PM_SLEEP
/*
 * 电源管理通知处理 - 系统休眠/唤醒时的安全处理
 * 在系统休眠前清除所有密钥，防止内存转储泄露
 */
static int wg_pm_notification(struct notifier_block *nb, unsigned long action,
			      void *data)
{
	struct wg_device *wg;
	struct wg_peer *peer;

	/* 如果机器频繁休眠/唤醒（如移动设备的正常操作），
	 * 而不是偶尔的事件，那么我们不希望清除密钥，
	 * 否则会影响正常的网络连接
	 */
	if (IS_ENABLED(CONFIG_PM_AUTOSLEEP) || IS_ENABLED(CONFIG_ANDROID))
		return 0;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	/* 遍历所有 WireGuard 设备，清除敏感的密钥材料 */
	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		mutex_lock(&wg->device_update_lock);
		list_for_each_entry(peer, &wg->peer_list, peer_list) {
			/* 取消密钥清零定时器 */
			del_timer(&peer->timer_zero_key_material);
			/* 立即清除握手状态 */
			wg_noise_handshake_clear(&peer->handshake);
			/* 清除所有传输密钥对 */
			wg_noise_keypairs_clear(&peer->keypairs);
		}
		mutex_unlock(&wg->device_update_lock);
	}
	rtnl_unlock();
	/* 等待所有 RCU 读取者完成，确保密钥完全清除 */
	rcu_barrier();
	return 0;
}

static struct notifier_block pm_notifier = { .notifier_call = wg_pm_notification };
#endif

/*
 * 网络设备关闭函数 - 当 'ip link set wg0 down' 时调用
 * 清理所有连接状态，停止定时器，释放队列中的数据包
 */
static int wg_stop(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	struct sk_buff *skb;

	mutex_lock(&wg->device_update_lock);
	/* 清理所有 peer 的状态 */
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		/* 清除待发送的数据包队列 */
		wg_packet_purge_staged_packets(peer);
		/* 停止所有定时器（keepalive, rekey 等）*/
		wg_timers_stop(peer);
		/* 清除握手状态 */
		wg_noise_handshake_clear(&peer->handshake);
		/* 清除传输密钥对 */
		wg_noise_keypairs_clear(&peer->keypairs);
		/* 重置最后发送握手的记录 */
		wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	}
	mutex_unlock(&wg->device_update_lock);
	/* 清空握手队列中剩余的数据包 */
	while ((skb = ptr_ring_consume(&wg->handshake_queue.ring)) != NULL)
		kfree_skb(skb);
	atomic_set(&wg->handshake_queue_len, 0);
	
	/* 重新初始化 socket（关闭监听）*/
	wg_socket_reinit(wg, NULL, NULL);
	return 0;
}

/*
 * 数据包传输函数 - WireGuard 的核心数据路径
 * 实现 cryptokey routing：根据目标 IP 查找对应的 peer，
 * 然后加密并通过 UDP 隧道发送数据包
 * 
 * aw:重点函数
 */
static netdev_tx_t wg_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct sk_buff_head packets;
	struct wg_peer *peer;
	struct sk_buff *next;
	sa_family_t family;
	u32 mtu;
	int ret;

	/* 检查数据包协议，只允许 IPv4 和 IPv6 */
	if (unlikely(!wg_check_packet_protocol(skb))) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	/* Cryptokey Routing 核心：根据目标 IP 查找对应的 peer */
	peer = wg_allowedips_lookup_dst(&wg->peer_allowedips, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		/* 记录无法路由的目标地址 */
		if (skb->protocol == htons(ETH_P_IP))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI4\n",
					    dev->name, &ip_hdr(skb)->daddr);
		else if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI6\n",
					    dev->name, &ipv6_hdr(skb)->daddr);
		goto err_icmp;
	}

	/* 检查 peer 是否有有效的端点地址 */
	family = READ_ONCE(peer->endpoint.addr.sa_family);
	if (unlikely(family != AF_INET && family != AF_INET6)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %llu\n",
				    dev->name, peer->internal_id);
		goto err_peer;
	}

	/* 获取有效的 MTU 大小 */
	mtu = skb_valid_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	/* 处理大数据包分段（GSO - Generic Segmentation Offload）*/
	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb)) {
		/* 普通数据包，直接处理 */
		skb_mark_not_on_list(skb);
	} else {
		/* GSO 数据包需要分段处理 */
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (IS_ERR(segs)) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		/* 释放原始大包，使用分段后的小包 */
		dev_kfree_skb(skb);
		skb = segs;
	}

	/* 处理每个数据包分段 */
	skb_list_walk_safe(skb, skb, next) {
		skb_mark_not_on_list(skb);

		/* 确保数据包可以安全修改（克隆检查）*/
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* 只有 ICMP 需要保留原始目标信息，
		 * 此时可以丢弃路由信息以节省内存
		 */
		skb_dst_drop(skb);

		/* 在数据包控制块中保存 MTU 信息 */
		PACKET_CB(skb)->mtu = mtu;

		/* 将处理好的数据包加入队列 */
		__skb_queue_tail(&packets, skb);
	}

	/* 将数据包添加到 peer 的待发送队列（aw-自旋锁） */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* 如果队列过大，删除最旧的数据包防止内存耗尽
	 * 在添加新包之前删除，避免删除刚分段的 GSO 包
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS) {
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
		++dev->stats.tx_dropped;
	}
	/* 将所有数据包加入 peer 的发送队列 */
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* 触发实际的数据包发送（加密和 UDP 传输）*/
	wg_packet_send_staged_packets(peer);

	/* 释放 peer 引用计数 */
	wg_peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	/* 释放 peer 引用 */
	wg_peer_put(peer);
err_icmp:
	/* 发送 ICMP 不可达消息通知发送方 */
	if (skb->protocol == htons(ETH_P_IP))
		icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_ndo_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
err:
	/* 更新错误统计 */
	++dev->stats.tx_errors;
	kfree_skb(skb);
	return ret;
}

/* WireGuard 网络设备操作函数表 */
static const struct net_device_ops netdev_ops = {
	.ndo_open		= wg_open,		/* 设备启动 */
	.ndo_stop		= wg_stop,		/* 设备关闭 */
	.ndo_start_xmit		= wg_xmit,		/* 数据包发送 */
	.ndo_get_stats64	= ip_tunnel_get_stats64	/* 统计信息获取 */
};

/*
 * 设备析构函数 - 完全销毁 WireGuard 设备时调用
 * 释放所有资源：工作队列、内存、peer 列表等
 */
static void wg_destruct(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);

	/* 从全局设备列表中移除 */
	rtnl_lock();
	list_del(&wg->device_list);
	rtnl_unlock();
	
	mutex_lock(&wg->device_update_lock);
	/* 清除网络命名空间引用 */
	rcu_assign_pointer(wg->creating_net, NULL);
	/* 重置端口和 socket */
	wg->incoming_port = 0;
	wg_socket_reinit(wg, NULL, NULL);
	/* 工作队列销毁会清除最终的引用计数 */
	wg_peer_remove_all(wg);
	
	/* 销毁所有工作队列 */
	destroy_workqueue(wg->handshake_receive_wq);
	destroy_workqueue(wg->handshake_send_wq);
	destroy_workqueue(wg->packet_crypt_wq);
	
	/* 释放数据包队列 */
	wg_packet_queue_free(&wg->handshake_queue, true);
	wg_packet_queue_free(&wg->decrypt_queue, false);
	wg_packet_queue_free(&wg->encrypt_queue, false);
	
	/* 等待所有 peer 实际释放完成 */
	rcu_barrier();
	
	/* 清理其他资源 */
	wg_ratelimiter_uninit();
	/* 安全清零静态身份信息（私钥等）*/
	memzero_explicit(&wg->static_identity, sizeof(wg->static_identity));
	/* 释放统计信息结构 */
	free_percpu(dev->tstats);
	/* 释放哈希表 */
	kvfree(wg->index_hashtable);
	kvfree(wg->peer_hashtable);
	mutex_unlock(&wg->device_update_lock);

	pr_debug("%s: Interface destroyed\n", dev->name);
	free_netdev(dev);
}

static const struct device_type device_type = { .name = KBUILD_MODNAME };

/*
 * 设备设置函数 - 配置 WireGuard 网络设备的基本属性
 * 设置 MTU、特性标志、头部空间等网络设备参数
 */
static void wg_setup(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	/* WireGuard 支持的网络设备特性 */
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };
	/* 计算协议开销：WireGuard消息头 + UDP头 + IP头 */
	const int overhead = MESSAGE_MINIMUM_LENGTH + sizeof(struct udphdr) +
			     max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	/* 设置网络设备基本参数 */
	dev->netdev_ops = &netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;		/* 无硬件头 */
	dev->addr_len = 0;			/* 无MAC地址 */
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;	/* 加密所需头部空间 */
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);	/* 尾部空间 */
	dev->type = ARPHRD_NONE;		/* 无ARP协议 */
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;	/* 点对点接口，无ARP */
#ifndef COMPAT_CANNOT_USE_IFF_NO_QUEUE
	dev->priv_flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	/* 设置 MTU：以太网数据长度减去协议开销 */
	dev->mtu = ETH_DATA_LEN - overhead;
#ifndef COMPAT_CANNOT_USE_MAX_MTU
	/* 设置最大 MTU，考虑消息填充对齐 */
	dev->max_mtu = round_down(INT_MAX, MESSAGE_PADDING_MULTIPLE) - overhead;
#endif

	/* 设置设备类型 */
	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* 保留目标路由信息用于 ICMP 回复 */
	netif_keep_dst(dev);

	/* 初始化 WireGuard 设备结构 */
	memset(wg, 0, sizeof(*wg));
	wg->dev = dev;
}

/*
 * 创建新的 WireGuard 链路 - 通过 netlink 接口调用
 * 分配和初始化所有必要的资源：哈希表、工作队列、数据包队列等
 */
static int wg_newlink(struct net *src_net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct wg_device *wg = netdev_priv(dev);
	int ret = -ENOMEM;

	/* 设置创建网络命名空间的引用 */
	rcu_assign_pointer(wg->creating_net, src_net);
	
	/* 初始化各种锁和同步原语 */
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	
	/* 初始化 AllowedIPs 路由表 */
	wg_allowedips_init(&wg->peer_allowedips);
	/* 初始化 cookie 检查器（DoS 防护）*/
	wg_cookie_checker_init(&wg->cookie_checker, wg);
	/* 初始化 peer 列表 */
	INIT_LIST_HEAD(&wg->peer_list);
	/* 设备更新代数，用于配置变更检测 */
	wg->device_update_gen = 1;

	/* 分配 peer 公钥哈希表 */
	wg->peer_hashtable = wg_pubkey_hashtable_alloc();
	if (!wg->peer_hashtable)
		return ret;

	/* 分配会话索引哈希表 */
	wg->index_hashtable = wg_index_hashtable_alloc();
	if (!wg->index_hashtable)
		goto err_free_peer_hashtable;

	/* 分配网络统计信息结构 */
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto err_free_index_hashtable;

	/* 创建握手接收工作队列（CPU密集型，可冻结）*/
	wg->handshake_receive_wq = alloc_workqueue("wg-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_receive_wq)
		goto err_free_tstats;

	/* 创建握手发送工作队列（不绑定CPU，可冻结）*/
	wg->handshake_send_wq = alloc_workqueue("wg-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_send_wq)
		goto err_destroy_handshake_receive;

	/* 创建数据包加密工作队列（CPU密集型，内存回收友好）*/
	wg->packet_crypt_wq = alloc_workqueue("wg-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!wg->packet_crypt_wq)
		goto err_destroy_handshake_send;

	/* 初始化加密队列 */
	ret = wg_packet_queue_init(&wg->encrypt_queue, wg_packet_encrypt_worker,
				   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	/* 初始化解密队列 */
	ret = wg_packet_queue_init(&wg->decrypt_queue, wg_packet_decrypt_worker,
				   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;

	/* 初始化握手处理队列 */
	ret = wg_packet_queue_init(&wg->handshake_queue, wg_packet_handshake_receive_worker,
				   MAX_QUEUED_INCOMING_HANDSHAKES);
	if (ret < 0)
		goto err_free_decrypt_queue;

	/* 初始化速率限制器（DoS 防护）*/
	ret = wg_ratelimiter_init();
	if (ret < 0)
		goto err_free_handshake_queue;

	/* 注册网络设备到内核 */
	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	/* 添加到全局设备列表 */
	list_add(&wg->device_list, &device_list);

	/* 等到最后才设置析构函数，避免注册失败时被误调用 */
	dev->priv_destructor = wg_destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

err_uninit_ratelimiter:
	wg_ratelimiter_uninit();
err_free_handshake_queue:
	wg_packet_queue_free(&wg->handshake_queue, false);
err_free_decrypt_queue:
	wg_packet_queue_free(&wg->decrypt_queue, false);
err_free_encrypt_queue:
	wg_packet_queue_free(&wg->encrypt_queue, false);
err_destroy_packet_crypt:
	destroy_workqueue(wg->packet_crypt_wq);
err_destroy_handshake_send:
	destroy_workqueue(wg->handshake_send_wq);
err_destroy_handshake_receive:
	destroy_workqueue(wg->handshake_receive_wq);
err_free_tstats:
	free_percpu(dev->tstats);
err_free_index_hashtable:
	kvfree(wg->index_hashtable);
err_free_peer_hashtable:
	kvfree(wg->peer_hashtable);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wg_device),
	.setup			= wg_setup,
	.newlink		= wg_newlink,
};

/*
 * 网络命名空间退出前处理
 * 当网络命名空间即将销毁时，清理相关的 WireGuard 设备
 */
static void wg_netns_pre_exit(struct net *net)
{
	struct wg_device *wg;
	struct wg_peer *peer;

	rtnl_lock();
	/* 遍历所有设备，找到属于即将退出的网络命名空间的设备 */
	list_for_each_entry(wg, &device_list, device_list) {
		if (rcu_access_pointer(wg->creating_net) == net) {
			pr_debug("%s: Creating namespace exiting\n", wg->dev->name);
			/* 关闭载波信号，标记网络不可用 */
			netif_carrier_off(wg->dev);
			mutex_lock(&wg->device_update_lock);
			/* 清除网络命名空间引用 */
			rcu_assign_pointer(wg->creating_net, NULL);
			/* 重新初始化 socket */
			wg_socket_reinit(wg, NULL, NULL);
			/* 清除所有 peer 的端点源地址 */
			list_for_each_entry(peer, &wg->peer_list, peer_list)
				wg_socket_clear_peer_endpoint_src(peer);
			mutex_unlock(&wg->device_update_lock);
		}
	}
	rtnl_unlock();
}

static struct pernet_operations pernet_ops = {
	.pre_exit = wg_netns_pre_exit
};

/*
 * WireGuard 设备子系统初始化
 * 注册电源管理通知、网络命名空间操作和 RTNL 链路操作
 */
int __init wg_device_init(void)
{
	int ret;

#ifdef CONFIG_PM_SLEEP
	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;
#endif

	ret = register_pernet_device(&pernet_ops);
	if (ret)
		goto error_pm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_pernet;

	return 0;

error_pernet:
	unregister_pernet_device(&pernet_ops);
error_pm:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	return ret;
}

/*
 * WireGuard 设备子系统清理
 * 注销所有已注册的通知器和操作函数
 */
void wg_device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	unregister_pernet_device(&pernet_ops);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	rcu_barrier();
}
