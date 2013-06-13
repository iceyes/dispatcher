#define KMSG_COMPONENT "DISPATCHER"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/route.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#ifdef CONFIG_DISPATCHER_IPV6
#include <net/ipv6.h>
#include <linux/netfilter_ipv6.h>
#endif

#include "../include/net/dispatcher.h"


#ifdef CONFIG_DISPATCHER_DEBUG
EXPORT_SYMBOL(dispatcher_get_debug_level);
#endif

const char *dispatcher_proto_name(unsigned proto)
{
	static char buf[20];

	switch (proto) {
	case IPPROTO_IP:
		return "IP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_ICMP:
		return "ICMP";
#ifdef CONFIG_DISPATCHER_IPV6
	case IPPROTO_ICMPV6:
		return "ICMPv6";
#endif
	default:
		sprintf(buf, "IP_%d", proto);
		return buf;
	}
}

/* Handle response packets: rewrite addresses and send away...
 * Used for NAT and local client.
 */
static unsigned int
handle_response(int af, struct sk_buff *skb, struct dispatcher_protocol *pp, struct dispatcher_dest *dest, int ihl)
{
	DISPATCHER_DBG_PKT(11, pp, skb, 0, "Outgoing packet");

	if (!skb_make_writable(skb, ihl))
		goto drop;

	/* mangle the packet */
	if (pp->snat_handler && !pp->snat_handler(skb, pp, dest->svc))
		goto drop;

#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		ipv6_hdr(skb)->saddr = dest->vaddr.in6;
	else
#endif
	{
		ip_hdr(skb)->saddr = dest->vaddr.ip;
		ip_send_check(ip_hdr(skb));
	}

	/* For policy routing, packets originating from this
	 * machine itself may be routed differently to packets
	 * passing through.  We want this packet to be routed as
	 * if it came from this machine itself.  So re-compute
	 * the routing information.
	 */
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6) {
		if (ip6_route_me_harder(skb) != 0)
			goto drop;
	} else
#endif
		if (ip_route_me_harder(skb, RTN_LOCAL) != 0)
			goto drop;

	DISPATCHER_DBG_PKT(10, pp, skb, 0, "After SNAT");

	LeaveFunction(11);
	return NF_ACCEPT;

drop:
	kfree_skb(skb);
	return NF_STOLEN;
}

/*
 *	It is hooked at the NF_INET_FORWARD chain, used only for VS/NAT.
 *	Check if outgoing packet belongs to the established dispatcher_conn.
 */
static unsigned int
dispatcher_out(unsigned int hooknum, struct sk_buff *skb,
	  const struct net_device *in, const struct net_device *out,
	  int (*okfn)(struct sk_buff *))
{
	struct dispatcher_iphdr iph;
	struct dispatcher_protocol *pp;
	struct tcphdr _tcph, *th;
	struct dispatcher_dest *dest;
	int af;

	EnterFunction(11);

	//af = (((struct iphdr *)skb_network_header(skb))->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;
	af = AF_INET;

	dispatcher_fill_iphdr(af, skb_network_header(skb), &iph);

	pp = dispatcher_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;
	th = skb_header_pointer(skb, iph.len, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		return NF_ACCEPT;
	}
	if(!(dest = dispatcher_lookup_real_service(af, iph.protocol, &iph.saddr, htons((ntohs(th->source))/100))))
		return NF_ACCEPT;

	return handle_response(af, skb, pp, dest, iph.len);
}

static unsigned int
dispatcher_in(unsigned int hooknum, struct sk_buff *skb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	struct dispatcher_iphdr iph;
	struct dispatcher_service *svc = NULL;
	struct dispatcher_protocol *pp = NULL;
	struct dispatcher_dest *dest;
	int af, ret;


	af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

	dispatcher_fill_iphdr(af, skb_network_header(skb), &iph);

	if (unlikely(skb->pkt_type != PACKET_HOST)) {
		DISPATCHER_DBG_BUF(12, "packet type=%d proto=%d daddr=%s ignored\n",
			      skb->pkt_type,
			      iph.protocol,
			      DISPATCHER_DBG_ADDR(af, &iph.daddr));
		return NF_ACCEPT;
	}

	pp = dispatcher_proto_get(iph.protocol);
	if (unlikely(!pp))
		return NF_ACCEPT;

	svc = pp->get_service(af, skb, &iph);

	if(unlikely(!svc))
		return NF_ACCEPT;
	dest = dispatcher_get_dest_from_svc(svc);
	/* Check the server status */
	if (!dest) {// || (dest && !(dest->flags & DISPATCHER_DEST_F_AVAILABLE))) {
		dispatcher_service_put(svc);
		return NF_DROP;
	}

	if (dest->packet_nat) {
		ret = dest->packet_nat(skb, svc, pp);
		/* do not touch skb anymore */
	}
	else {
		DISPATCHER_DBG_RL("warning: packet_nat is null");
		ret = NF_DROP;
	}
	dispatcher_service_put(svc);
	dispatcher_dest_put(dest);

	return ret;
}



static struct nf_hook_ops dispatcher_ops[] __read_mostly = {
	/* After packet filtering, forward packet through VS/DR, VS/TUN,
	 * or VS/NAT(change destination), so that filtering rules can be
	 * applied to DISPATCHER. */
	{
		.hook		= dispatcher_in,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum        = NF_INET_LOCAL_IN,
		.priority       = 100,
	},
	/* After packet filtering, change source only for VS/NAT */
	{
		.hook		= dispatcher_out,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum        = NF_INET_LOCAL_OUT,
		.priority       = 100,
	},
};


/*
 *	Initialize IP Virtual Server
 */
static int __init dispatcher_init(void)
{
	int ret;
	ret = dispatcher_control_init();
	dispatcher_protocol_init();

	ret = nf_register_hooks(dispatcher_ops, ARRAY_SIZE(dispatcher_ops));
	if (ret < 0) {
		pr_err("can't register hooks.\n");
		goto cleanup_protocol;
	}

	pr_info("dispatcher loaded.\n");
	return ret;
  cleanup_protocol:
	dispatcher_protocol_cleanup();
	return ret;
}

static void __exit dispatcher_cleanup(void)
{
	nf_unregister_hooks(dispatcher_ops, ARRAY_SIZE(dispatcher_ops));
	dispatcher_control_cleanup();
	dispatcher_protocol_cleanup();
	pr_info("dispatcher unloaded.\n");
}

module_init(dispatcher_init);
module_exit(dispatcher_cleanup);
MODULE_LICENSE("GPL");
