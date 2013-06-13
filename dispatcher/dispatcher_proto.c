/*
 * dispatcher_proto.c: transport protocol load balancing support for DISPATCHER
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/system.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>

#include "../include/net/dispatcher.h"


/*
 * DISPATCHER protocols can only be registered/unregistered when the dispatcher
 * module is loaded/unloaded, so no lock is needed in accessing the
 * dispatcher protocol table.
 */

#define DISPATCHER_PROTO_TAB_SIZE		32	/* must be power of 2 */
#define DISPATCHER_PROTO_HASH(proto)		((proto) & (DISPATCHER_PROTO_TAB_SIZE-1))

static struct dispatcher_protocol *dispatcher_proto_table[DISPATCHER_PROTO_TAB_SIZE];


/*
 *	register an dispatcher protocol
 */
static int __used __init register_dispatcher_protocol(struct dispatcher_protocol *pp)
{
	unsigned hash = DISPATCHER_PROTO_HASH(pp->protocol);

	pp->next = dispatcher_proto_table[hash];
	dispatcher_proto_table[hash] = pp;

	if (pp->init != NULL)
		pp->init(pp);

	return 0;
}


/*
 *	unregister an dispatcher protocol
 */
static int unregister_dispatcher_protocol(struct dispatcher_protocol *pp)
{
	struct dispatcher_protocol **pp_p;
	unsigned hash = DISPATCHER_PROTO_HASH(pp->protocol);

	pp_p = &dispatcher_proto_table[hash];
	for (; *pp_p; pp_p = &(*pp_p)->next) {
		if (*pp_p == pp) {
			*pp_p = pp->next;
			if (pp->exit != NULL)
				pp->exit(pp);
			return 0;
		}
	}

	return -ESRCH;
}


/*
 *	get dispatcher_protocol object by its proto.
 */
struct dispatcher_protocol * dispatcher_proto_get(unsigned short proto)
{
	struct dispatcher_protocol *pp;
	unsigned hash = DISPATCHER_PROTO_HASH(proto);

	for (pp = dispatcher_proto_table[hash]; pp; pp = pp->next) {
		if (pp->protocol == proto)
			return pp;
	}

	return NULL;
}

static void
dispatcher_tcpudp_debug_packet_v4(struct dispatcher_protocol *pp,
			     const struct sk_buff *skb,
			     int offset,
			     const char *msg)
{
	char buf[128];
	struct iphdr _iph, *ih;

	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (ih == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else if (ih->frag_off & htons(IP_OFFSET))
		sprintf(buf, "%s %pI4->%pI4 frag",
			pp->name, &ih->saddr, &ih->daddr);
	else {
		__be16 _ports[2], *pptr
;
		pptr = skb_header_pointer(skb, offset + ih->ihl*4,
					  sizeof(_ports), _ports);
		if (pptr == NULL)
			sprintf(buf, "%s TRUNCATED %pI4->%pI4",
				pp->name, &ih->saddr, &ih->daddr);
		else
			sprintf(buf, "%s %pI4:%u->%pI4:%u",
				pp->name,
				&ih->saddr, ntohs(pptr[0]),
				&ih->daddr, ntohs(pptr[1]));
	}

	pr_debug("%s: %s\n", msg, buf);
}

#ifdef CONFIG_DISPATCHER_IPV6
static void
dispatcher_tcpudp_debug_packet_v6(struct dispatcher_protocol *pp,
			     const struct sk_buff *skb,
			     int offset,
			     const char *msg)
{
	char buf[192];
	struct ipv6hdr _iph, *ih;

	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (ih == NULL)
		sprintf(buf, "%s TRUNCATED", pp->name);
	else if (ih->nexthdr == IPPROTO_FRAGMENT)
		sprintf(buf, "%s %pI6->%pI6 frag",
			pp->name, &ih->saddr, &ih->daddr);
	else {
		__be16 _ports[2], *pptr;

		pptr = skb_header_pointer(skb, offset + sizeof(struct ipv6hdr),
					  sizeof(_ports), _ports);
		if (pptr == NULL)
			sprintf(buf, "%s TRUNCATED %pI6->%pI6",
				pp->name, &ih->saddr, &ih->daddr);
		else
			sprintf(buf, "%s %pI6:%u->%pI6:%u",
				pp->name,
				&ih->saddr, ntohs(pptr[0]),
				&ih->daddr, ntohs(pptr[1]));
	}

	pr_debug("%s: %s\n", msg, buf);
}
#endif


void
dispatcher_tcpudp_debug_packet(struct dispatcher_protocol *pp,
			  const struct sk_buff *skb,
			  int offset,
			  const char *msg)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (skb->protocol == htons(ETH_P_IPV6))
		dispatcher_tcpudp_debug_packet_v6(pp, skb, offset, msg);
	else
#endif
		dispatcher_tcpudp_debug_packet_v4(pp, skb, offset, msg);
}


int __init dispatcher_protocol_init(void)
{
	char protocols[64];
#define REGISTER_PROTOCOL(p)			\
	do {					\
		register_dispatcher_protocol(p);	\
		strcat(protocols, ", ");	\
		strcat(protocols, (p)->name);	\
	} while (0)

	protocols[0] = '\0';
	protocols[2] = '\0';
#ifdef CONFIG_DISPATCHER_PROTO_TCP
	REGISTER_PROTOCOL(&dispatcher_protocol_tcp);
#endif
#if 0
#ifdef CONFIG_DISPATCHER_PROTO_UDP
	REGISTER_PROTOCOL(&dispatcher_protocol_udp);
#endif
#ifdef CONFIG_DISPATCHER_PROTO_AH
	REGISTER_PROTOCOL(&dispatcher_protocol_ah);
#endif
#ifdef CONFIG_DISPATCHER_PROTO_ESP
	REGISTER_PROTOCOL(&dispatcher_protocol_esp);
#endif
#endif
	pr_info("Registered protocols (%s)\n", &protocols[2]);

	return 0;
}


void dispatcher_protocol_cleanup(void)
{
	struct dispatcher_protocol *pp;
	int i;

	/* unregister all the dispatcher protocols */
	for (i = 0; i < DISPATCHER_PROTO_TAB_SIZE; i++) {
		while ((pp = dispatcher_proto_table[i]) != NULL)
			unregister_dispatcher_protocol(pp);
	}
}
