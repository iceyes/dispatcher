/*
 * dispatcher_proto_tcp.c:	TCP load balancing support for DISPATCHER
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
#include <linux/ip.h>
#include <linux/tcp.h>                  /* for tcphdr */
#include <net/ip.h>
#include <net/tcp.h>                    /* for csum_tcpudp_magic */
#include <net/ip6_checksum.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "../include/net/dispatcher.h"

static inline void
tcp_fast_csum_update(int af, struct tcphdr *tcph,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldport, __be16 newport)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		tcph->check =
			csum_fold(dispatcher_check_diff16(oldip->ip6, newip->ip6,
					 dispatcher_check_diff2(oldport, newport,
						~csum_unfold(tcph->check))));
	else
#endif
	tcph->check =
		csum_fold(dispatcher_check_diff4(oldip->ip, newip->ip,
				 dispatcher_check_diff2(oldport, newport,
						~csum_unfold(tcph->check))));
}


static inline void
tcp_partial_csum_update(int af, struct tcphdr *tcph,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldlen, __be16 newlen)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		tcph->check =
			csum_fold(dispatcher_check_diff16(oldip->ip6, newip->ip6,
					 dispatcher_check_diff2(oldlen, newlen,
						~csum_unfold(tcph->check))));
	else
#endif
	tcph->check =
		csum_fold(dispatcher_check_diff4(oldip->ip, newip->ip,
				dispatcher_check_diff2(oldlen, newlen,
						~csum_unfold(tcph->check))));
}


static int
tcp_snat_handler(struct sk_buff *skb,
		 struct dispatcher_protocol *pp, struct dispatcher_service *svc)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;
	__be16 localport;
	struct dispatcher_dest *dest = svc->dest;

#ifdef CONFIG_DISPATCHER_IPV6
	if (svc->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff+sizeof(*tcph)))
		return 0;

	tcph = (void *)skb_network_header(skb) + tcphoff;
	localport = tcph->source;
	tcph->source = svc->port;

	/* Adjust TCP checksums */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		//tcp_partial_csum_update(svc->af, tcph, &dest->addr, &svc->addr,
		//			htons(oldlen),
		//			htons(skb->len - tcphoff));
		tcph->check = 0;
		tcph->check = ~tcp_v4_check(skb->len - tcphoff, svc->addr.ip, ip_hdr(skb)->daddr, 0);
	} else {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(svc->af, tcph, &dest->addr, &svc->addr,
				     localport, svc->port);
		if (skb->ip_summed == CHECKSUM_COMPLETE) {
			skb->ip_summed = CHECKSUM_NONE;
		}
	}
	return 1;
}


static int
tcp_dnat_handler(struct sk_buff *skb,
		 struct dispatcher_protocol *pp, struct dispatcher_service *svc)
{
	struct tcphdr *tcph;
	unsigned int tcphoff;
	int oldlen;
	struct dispatcher_dest *dest = svc->dest;
	__be16 localport;
	
	localport = htons(htons(dest->port) * 100 + smp_processor_id());

#ifdef CONFIG_DISPATCHER_IPV6
	if (dest->af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);
	oldlen = skb->len - tcphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, tcphoff+sizeof(*tcph))) {
		return 0;
	}

	tcph = (void *)skb_network_header(skb) + tcphoff;
	tcph->dest = localport;

	/*
	 *	Adjust TCP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcp_partial_csum_update(dest->af, tcph, &svc->addr, &dest->addr,
					htons(oldlen),
					htons(skb->len - tcphoff));
	} else {
		/* Only port and addr are changed, do fast csum update */
		tcp_fast_csum_update(dest->af, tcph, &svc->addr, &dest->addr,
				     svc->port, localport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	}
	return 1;
}


static int
tcp_csum_check(int af, struct sk_buff *skb, struct dispatcher_protocol *pp)
{
	unsigned int tcphoff;

#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		tcphoff = sizeof(struct ipv6hdr);
	else
#endif
		tcphoff = ip_hdrlen(skb);

	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
	case CHECKSUM_COMPLETE:
#ifdef CONFIG_DISPATCHER_IPV6
		if (af == AF_INET6) {
			if (csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
					    &ipv6_hdr(skb)->daddr,
					    skb->len - tcphoff,
					    ipv6_hdr(skb)->nexthdr,
					    skb->csum)) {
				DISPATCHER_DBG_RL_PKT(0, pp, skb, 0,
						 "Failed checksum for");
				return 0;
			}
		} else
#endif
			if (csum_tcpudp_magic(ip_hdr(skb)->saddr,
					      ip_hdr(skb)->daddr,
					      skb->len - tcphoff,
					      ip_hdr(skb)->protocol,
					      skb->csum)) {
				DISPATCHER_DBG_RL_PKT(0, pp, skb, 0,
						 "Failed checksum for");
				return 0;
			}
		break;
	default:
		/* No need to checksum. */
		break;
	}

	return 1;
}

static void dispatcher_tcp_init(struct dispatcher_protocol *pp)
{
}


static void dispatcher_tcp_exit(struct dispatcher_protocol *pp)
{
}

static struct dispatcher_service * dispatcher_tcp_get_service(int af, struct sk_buff *skb, struct dispatcher_iphdr *iph)
{
	struct dispatcher_service *svc = NULL;
	struct tcphdr _tcph, *th;
	th = skb_header_pointer(skb, iph->len, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		return NULL;
	}

	svc = dispatcher_service_get(af, iph->protocol, &iph->daddr, th->dest);
	return svc;

}


struct dispatcher_protocol dispatcher_protocol_tcp = {
	.name =			"TCP",
	.protocol =		IPPROTO_TCP,
	.init =			dispatcher_tcp_init,
	.exit =			dispatcher_tcp_exit,
	.get_service =			dispatcher_tcp_get_service,
	.snat_handler =		tcp_snat_handler,
	.dnat_handler =		tcp_dnat_handler,
	.csum_check =		tcp_csum_check,
	.debug_packet =		dispatcher_tcpudp_debug_packet,
};
