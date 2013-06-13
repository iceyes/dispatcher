/*
 * dispatcher_proto_udp.c:	UDP load balancing support for DISPATCHER
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

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>

#include "../include/net/dispatcher.h"
#include <net/ip.h>
#include <net/ip6_checksum.h>

static struct dispatcher_conn *
udp_conn_in_get(int af, const struct sk_buff *skb, struct dispatcher_protocol *pp,
		const struct dispatcher_iphdr *iph, unsigned int proto_off,
		int inverse)
{
	struct dispatcher_conn *cp;
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		cp = dispatcher_conn_in_get(af, iph->protocol,
				       &iph->saddr, pptr[0],
				       &iph->daddr, pptr[1]);
	} else {
		cp = dispatcher_conn_in_get(af, iph->protocol,
				       &iph->daddr, pptr[1],
				       &iph->saddr, pptr[0]);
	}

	return cp;
}


static struct dispatcher_conn *
udp_conn_out_get(int af, const struct sk_buff *skb, struct dispatcher_protocol *pp,
		 const struct dispatcher_iphdr *iph, unsigned int proto_off,
		 int inverse)
{
	struct dispatcher_conn *cp;
	__be16 _ports[2], *pptr;

	pptr = skb_header_pointer(skb, proto_off, sizeof(_ports), _ports);
	if (pptr == NULL)
		return NULL;

	if (likely(!inverse)) {
		cp = dispatcher_conn_out_get(af, iph->protocol,
					&iph->saddr, pptr[0],
					&iph->daddr, pptr[1]);
	} else {
		cp = dispatcher_conn_out_get(af, iph->protocol,
					&iph->daddr, pptr[1],
					&iph->saddr, pptr[0]);
	}

	return cp;
}


static int
udp_conn_schedule(int af, struct sk_buff *skb, struct dispatcher_protocol *pp,
		  int *verdict, struct dispatcher_conn **cpp)
{
#if 0
	struct dispatcher_service *svc;
	struct udphdr _udph, *uh;
	struct dispatcher_iphdr iph;

	dispatcher_fill_iphdr(af, skb_network_header(skb), &iph);

	uh = skb_header_pointer(skb, iph.len, sizeof(_udph), &_udph);
	if (uh == NULL) {
		*verdict = NF_DROP;
		return 0;
	}

	svc = dispatcher_service_get(af, iph.protocol,
				&iph.daddr, uh->dest);
	if (svc) {
		if (dispatcher_todrop()) {
			/*
			 * It seems that we are very loaded.
			 * We have to drop this packet :(
			 */
			dispatcher_service_put(svc);
			*verdict = NF_DROP;
			return 0;
		}

		/*
		 * Let the virtual server select a real server for the
		 * incoming connection, and create a connection entry.
		 */
		*cpp = dispatcher_schedule(svc, skb);
		if (!*cpp) {
			*verdict = dispatcher_leave(svc, skb, pp);
			return 0;
		}
		dispatcher_service_put(svc);
	}
#endif
	return 1;
}


static inline void
udp_fast_csum_update(int af, struct udphdr *uhdr,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldport, __be16 newport)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		uhdr->check =
			csum_fold(dispatcher_check_diff16(oldip->ip6, newip->ip6,
					 dispatcher_check_diff2(oldport, newport,
						~csum_unfold(uhdr->check))));
	else
#endif
		uhdr->check =
			csum_fold(dispatcher_check_diff4(oldip->ip, newip->ip,
					 dispatcher_check_diff2(oldport, newport,
						~csum_unfold(uhdr->check))));
	if (!uhdr->check)
		uhdr->check = CSUM_MANGLED_0;
}

static inline void
udp_partial_csum_update(int af, struct udphdr *uhdr,
		     const union nf_inet_addr *oldip,
		     const union nf_inet_addr *newip,
		     __be16 oldlen, __be16 newlen)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		uhdr->check =
			csum_fold(dispatcher_check_diff16(oldip->ip6, newip->ip6,
					 dispatcher_check_diff2(oldlen, newlen,
						~csum_unfold(uhdr->check))));
	else
#endif
	uhdr->check =
		csum_fold(dispatcher_check_diff4(oldip->ip, newip->ip,
				dispatcher_check_diff2(oldlen, newlen,
						~csum_unfold(uhdr->check))));
}


static int
udp_snat_handler(struct sk_buff *skb,
		 struct dispatcher_protocol *pp, struct dispatcher_conn *cp)
{
	struct udphdr *udph;
	unsigned int udphoff;
	int oldlen;

#ifdef CONFIG_DISPATCHER_IPV6
	if (cp->af == AF_INET6)
		udphoff = sizeof(struct ipv6hdr);
	else
#endif
		udphoff = ip_hdrlen(skb);
	oldlen = skb->len - udphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, udphoff+sizeof(*udph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *	Call application helper if needed
		 */
		if (!dispatcher_app_pkt_out(cp, skb))
			return 0;
	}

	udph = (void *)skb_network_header(skb) + udphoff;
	udph->source = cp->vport;

	/*
	 *	Adjust UDP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		udp_partial_csum_update(cp->af, udph, &cp->daddr, &cp->vaddr,
					htons(oldlen),
					htons(skb->len - udphoff));
	} else if (!cp->app && (udph->check != 0)) {
		/* Only port and addr are changed, do fast csum update */
		udp_fast_csum_update(cp->af, udph, &cp->daddr, &cp->vaddr,
				     cp->dport, cp->vport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		udph->check = 0;
		skb->csum = skb_checksum(skb, udphoff, skb->len - udphoff, 0);
#ifdef CONFIG_DISPATCHER_IPV6
		if (cp->af == AF_INET6)
			udph->check = csum_ipv6_magic(&cp->vaddr.in6,
						      &cp->caddr.in6,
						      skb->len - udphoff,
						      cp->protocol, skb->csum);
		else
#endif
			udph->check = csum_tcpudp_magic(cp->vaddr.ip,
							cp->caddr.ip,
							skb->len - udphoff,
							cp->protocol,
							skb->csum);
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;
		DISPATCHER_DBG(11, "O-pkt: %s O-csum=%d (+%zd)\n",
			  pp->name, udph->check,
			  (char*)&(udph->check) - (char*)udph);
	}
	return 1;
}


static int
udp_dnat_handler(struct sk_buff *skb,
		 struct dispatcher_protocol *pp, struct dispatcher_conn *cp)
{
	struct udphdr *udph;
	unsigned int udphoff;
	int oldlen;

#ifdef CONFIG_DISPATCHER_IPV6
	if (cp->af == AF_INET6)
		udphoff = sizeof(struct ipv6hdr);
	else
#endif
		udphoff = ip_hdrlen(skb);
	oldlen = skb->len - udphoff;

	/* csum_check requires unshared skb */
	if (!skb_make_writable(skb, udphoff+sizeof(*udph)))
		return 0;

	if (unlikely(cp->app != NULL)) {
		/* Some checks before mangling */
		if (pp->csum_check && !pp->csum_check(cp->af, skb, pp))
			return 0;

		/*
		 *	Attempt dispatcher_app call.
		 *	It will fix dispatcher_conn
		 */
		if (!dispatcher_app_pkt_in(cp, skb))
			return 0;
	}

	udph = (void *)skb_network_header(skb) + udphoff;
	udph->dest = cp->dport;

	/*
	 *	Adjust UDP checksums
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		udp_partial_csum_update(cp->af, udph, &cp->daddr, &cp->vaddr,
					htons(oldlen),
					htons(skb->len - udphoff));
	} else if (!cp->app && (udph->check != 0)) {
		/* Only port and addr are changed, do fast csum update */
		udp_fast_csum_update(cp->af, udph, &cp->vaddr, &cp->daddr,
				     cp->vport, cp->dport);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->ip_summed = CHECKSUM_NONE;
	} else {
		/* full checksum calculation */
		udph->check = 0;
		skb->csum = skb_checksum(skb, udphoff, skb->len - udphoff, 0);
#ifdef CONFIG_DISPATCHER_IPV6
		if (cp->af == AF_INET6)
			udph->check = csum_ipv6_magic(&cp->caddr.in6,
						      &cp->daddr.in6,
						      skb->len - udphoff,
						      cp->protocol, skb->csum);
		else
#endif
			udph->check = csum_tcpudp_magic(cp->caddr.ip,
							cp->daddr.ip,
							skb->len - udphoff,
							cp->protocol,
							skb->csum);
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return 1;
}


static int
udp_csum_check(int af, struct sk_buff *skb, struct dispatcher_protocol *pp)
{
	struct udphdr _udph, *uh;
	unsigned int udphoff;

#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		udphoff = sizeof(struct ipv6hdr);
	else
#endif
		udphoff = ip_hdrlen(skb);

	uh = skb_header_pointer(skb, udphoff, sizeof(_udph), &_udph);
	if (uh == NULL)
		return 0;

	if (uh->check != 0) {
		switch (skb->ip_summed) {
		case CHECKSUM_NONE:
			skb->csum = skb_checksum(skb, udphoff,
						 skb->len - udphoff, 0);
		case CHECKSUM_COMPLETE:
#ifdef CONFIG_DISPATCHER_IPV6
			if (af == AF_INET6) {
				if (csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						    &ipv6_hdr(skb)->daddr,
						    skb->len - udphoff,
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
						      skb->len - udphoff,
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
	}
	return 1;
}


/*
 *	Note: the caller guarantees that only one of register_app,
 *	unregister_app or app_conn_bind is called each time.
 */

#define	UDP_APP_TAB_BITS	4
#define	UDP_APP_TAB_SIZE	(1 << UDP_APP_TAB_BITS)
#define	UDP_APP_TAB_MASK	(UDP_APP_TAB_SIZE - 1)

static struct list_head udp_apps[UDP_APP_TAB_SIZE];
static DEFINE_SPINLOCK(udp_app_lock);

static inline __u16 udp_app_hashkey(__be16 port)
{
	return (((__force u16)port >> UDP_APP_TAB_BITS) ^ (__force u16)port)
		& UDP_APP_TAB_MASK;
}


static int udp_register_app(struct dispatcher_app *inc)
{
	struct dispatcher_app *i;
	__u16 hash;
	__be16 port = inc->port;
	int ret = 0;

	hash = udp_app_hashkey(port);


	spin_lock_bh(&udp_app_lock);
	list_for_each_entry(i, &udp_apps[hash], p_list) {
		if (i->port == port) {
			ret = -EEXIST;
			goto out;
		}
	}
	list_add(&inc->p_list, &udp_apps[hash]);
	atomic_inc(&dispatcher_protocol_udp.appcnt);

  out:
	spin_unlock_bh(&udp_app_lock);
	return ret;
}


static void
udp_unregister_app(struct dispatcher_app *inc)
{
	spin_lock_bh(&udp_app_lock);
	atomic_dec(&dispatcher_protocol_udp.appcnt);
	list_del(&inc->p_list);
	spin_unlock_bh(&udp_app_lock);
}


static int udp_app_conn_bind(struct dispatcher_conn *cp)
{
	int hash;
	struct dispatcher_app *inc;
	int result = 0;

	/* Default binding: bind app only for NAT */
	if (DISPATCHER_FWD_METHOD(cp) != DISPATCHER_CONN_F_MASQ)
		return 0;

	/* Lookup application incarnations and bind the right one */
	hash = udp_app_hashkey(cp->vport);

	spin_lock(&udp_app_lock);
	list_for_each_entry(inc, &udp_apps[hash], p_list) {
		if (inc->port == cp->vport) {
			if (unlikely(!dispatcher_app_inc_get(inc)))
				break;
			spin_unlock(&udp_app_lock);

			DISPATCHER_DBG_BUF(9, "%s(): Binding conn %s:%u->"
				      "%s:%u to app %s on port %u\n",
				      __func__,
				      DISPATCHER_DBG_ADDR(cp->af, &cp->caddr),
				      ntohs(cp->cport),
				      DISPATCHER_DBG_ADDR(cp->af, &cp->vaddr),
				      ntohs(cp->vport),
				      inc->name, ntohs(inc->port));

			cp->app = inc;
			if (inc->init_conn)
				result = inc->init_conn(inc, cp);
			goto out;
		}
	}
	spin_unlock(&udp_app_lock);

  out:
	return result;
}


static int udp_timeouts[DISPATCHER_UDP_S_LAST+1] = {
	[DISPATCHER_UDP_S_NORMAL]		=	5*60*HZ,
	[DISPATCHER_UDP_S_LAST]		=	2*HZ,
};

static const char *const udp_state_name_table[DISPATCHER_UDP_S_LAST+1] = {
	[DISPATCHER_UDP_S_NORMAL]		=	"UDP",
	[DISPATCHER_UDP_S_LAST]		=	"BUG!",
};


static int
udp_set_state_timeout(struct dispatcher_protocol *pp, char *sname, int to)
{
	return dispatcher_set_state_timeout(pp->timeout_table, DISPATCHER_UDP_S_LAST,
				       udp_state_name_table, sname, to);
}

static const char * udp_state_name(int state)
{
	if (state >= DISPATCHER_UDP_S_LAST)
		return "ERR!";
	return udp_state_name_table[state] ? udp_state_name_table[state] : "?";
}

static int
udp_state_transition(struct dispatcher_conn *cp, int direction,
		     const struct sk_buff *skb,
		     struct dispatcher_protocol *pp)
{
	cp->timeout = pp->timeout_table[DISPATCHER_UDP_S_NORMAL];
	return 1;
}

static void udp_init(struct dispatcher_protocol *pp)
{
	DISPATCHER_INIT_HASH_TABLE(udp_apps);
	pp->timeout_table = udp_timeouts;
}

static void udp_exit(struct dispatcher_protocol *pp)
{
}


struct dispatcher_protocol dispatcher_protocol_udp = {
	.name =			"UDP",
	.protocol =		IPPROTO_UDP,
	.num_states =		DISPATCHER_UDP_S_LAST,
	.dont_defrag =		0,
	.init =			udp_init,
	.exit =			udp_exit,
	.conn_schedule =	udp_conn_schedule,
	.conn_in_get =		udp_conn_in_get,
	.conn_out_get =		udp_conn_out_get,
	.snat_handler =		udp_snat_handler,
	.dnat_handler =		udp_dnat_handler,
	.csum_check =		udp_csum_check,
	.state_transition =	udp_state_transition,
	.state_name =		udp_state_name,
	.register_app =		udp_register_app,
	.unregister_app =	udp_unregister_app,
	.app_conn_bind =	udp_app_conn_bind,
	.debug_packet =		dispatcher_tcpudp_debug_packet,
	.timeout_change =	NULL,
	.set_state_timeout =	udp_set_state_timeout,
};
