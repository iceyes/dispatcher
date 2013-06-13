/*
 * dispatcher_xmit.c: various packet transmitters for DISPATCHER
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "DISPATCHER"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/tcp.h>                  /* for tcphdr */
#include <net/ip.h>
#include <net/tcp.h>                    /* for csum_tcpudp_magic */
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/route.h>                  /* for ip_route_output */
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "../include/net/dispatcher.h"

/*
 *      NULL transmitter (do nothing except return NF_ACCEPT)
 */
int
dispatcher_null_nat(struct sk_buff *skb, struct dispatcher_service *svc,
		struct dispatcher_protocol *pp)
{
	/* we do not touch skb and do not need pskb ptr */
	return NF_ACCEPT;
}

/*
 *      NAT transmitter (only for outside-to-inside nat forwarding)
 *      Not used for related ICMP
 */
int
dispatcher_nat(struct sk_buff *skb, struct dispatcher_service *svc,
	       struct dispatcher_protocol *pp)
{
	EnterFunction(10);

	if (!skb_make_writable(skb, sizeof(struct iphdr)))
		goto tx_error;

	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, svc))
		goto tx_error;
	ip_hdr(skb)->daddr = svc->dest->addr.ip;
	ip_send_check(ip_hdr(skb));

	DISPATCHER_DBG_PKT(10, pp, skb, 0, "After DNAT");

	LeaveFunction(10);
	return NF_ACCEPT;

  tx_error:
	LeaveFunction(10);
	return NF_DROP;
}

#ifdef CONFIG_DISPATCHER_IPV6
int
dispatcher_nat_v6(struct sk_buff *skb, struct dispatcher_service *svc,
		  struct dispatcher_protocol *pp)
{
	EnterFunction(10);

	if (!skb_make_writable(skb, sizeof(struct ipv6hdr)))
		goto tx_error_put;

	if (pp->dnat_handler && !pp->dnat_handler(skb, pp, svc))
		goto tx_error;
	ipv6_hdr(skb)->daddr = svc->dest->addr.in6;

	DISPATCHER_DBG_PKT(10, pp, skb, 0, "After DNAT");

	LeaveFunction(10);
	return NF_ACCEPT;

tx_error:
	LeaveFunction(10);
	return NF_DROP;
}
#endif
