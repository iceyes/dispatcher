/*
 *      IP Virtual Server
 *      data structure and functionality definitions
 */

#ifndef _NET_DISPATCHER_H
#define _NET_DISPATCHER_H

#include "../linux/dispatcher.h"                /* definitions shared with userland */

/* old dispatcheradm versions still include this file directly */
#ifdef __KERNEL__

#include <asm/types.h>                  /* for __uXX types */

#include <linux/sysctl.h>               /* for ctl_path */
#include <linux/list.h>                 /* for struct list_head */
#include <linux/spinlock.h>             /* for struct rwlock_t */
#include <asm/atomic.h>                 /* for struct atomic_t */
#include <linux/compiler.h>
#include <linux/timer.h>

#include <net/checksum.h>
#include <linux/netfilter.h>		/* for union nf_inet_addr */
#include <linux/ip.h>
#include <linux/ipv6.h>			/* for struct ipv6hdr */
#include <net/ipv6.h>			/* for ipv6_addr_copy */

struct dispatcher_iphdr {
	int len;
	__u8 protocol;
	union nf_inet_addr saddr;
	union nf_inet_addr daddr;
};

static inline void
dispatcher_fill_iphdr(int af, const void *nh, struct dispatcher_iphdr *iphdr)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6) {
		const struct ipv6hdr *iph = nh;
		iphdr->len = sizeof(struct ipv6hdr);
		iphdr->protocol = iph->nexthdr;
		ipv6_addr_copy(&iphdr->saddr.in6, &iph->saddr);
		ipv6_addr_copy(&iphdr->daddr.in6, &iph->daddr);
	} else
#endif
	{
		const struct iphdr *iph = nh;
		iphdr->len = iph->ihl * 4;
		iphdr->protocol = iph->protocol;
		iphdr->saddr.ip = iph->saddr;
		iphdr->daddr.ip = iph->daddr;
	}
}

static inline void dispatcher_addr_copy(int af, union nf_inet_addr *dst,
				   const union nf_inet_addr *src)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		ipv6_addr_copy(&dst->in6, &src->in6);
	else
#endif
	dst->ip = src->ip;
}

static inline int dispatcher_addr_equal(int af, const union nf_inet_addr *a,
				   const union nf_inet_addr *b)
{
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		return ipv6_addr_equal(&a->in6, &b->in6);
#endif
	return a->ip == b->ip;
}

#ifdef CONFIG_DISPATCHER_DEBUG
#include <linux/net.h>

extern int dispatcher_get_debug_level(void);

static inline const char *dispatcher_dbg_addr(int af, char *buf, size_t buf_len,
					 const union nf_inet_addr *addr,
					 int *idx)
{
	int len;
#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		len = snprintf(&buf[*idx], buf_len - *idx, "[%pI6]",
			       &addr->in6) + 1;
	else
#endif
		len = snprintf(&buf[*idx], buf_len - *idx, "%pI4",
			       &addr->ip) + 1;

	*idx += len;
	BUG_ON(*idx > buf_len + 1);
	return &buf[*idx - len];
}

#define DISPATCHER_DBG_BUF(level, msg, ...)					\
	do {								\
		char dispatcher_dbg_buf[160];				\
		int dispatcher_dbg_idx = 0;					\
		if (level <= dispatcher_get_debug_level())			\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define DISPATCHER_ERR_BUF(msg...)						\
	do {								\
		char dispatcher_dbg_buf[160];				\
		int dispatcher_dbg_idx = 0;					\
		pr_err(msg);						\
	} while (0)

/* Only use from within DISPATCHER_DBG_BUF() or DISPATCHER_ERR_BUF macros */
#define DISPATCHER_DBG_ADDR(af, addr)					\
	dispatcher_dbg_addr(af, dispatcher_dbg_buf,				\
		       sizeof(dispatcher_dbg_buf), addr,			\
		       &dispatcher_dbg_idx)

#define DISPATCHER_DBG(level, msg, ...)					\
	do {								\
		if (level <= dispatcher_get_debug_level())			\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define DISPATCHER_DBG_RL(msg, ...)						\
	do {								\
		if (net_ratelimit())					\
			printk(KERN_DEBUG pr_fmt(msg), ##__VA_ARGS__);	\
	} while (0)
#define DISPATCHER_DBG_PKT(level, pp, skb, ofs, msg)				\
	do {								\
		if (level <= dispatcher_get_debug_level())			\
			pp->debug_packet(pp, skb, ofs, msg);		\
	} while (0)
#define DISPATCHER_DBG_RL_PKT(level, pp, skb, ofs, msg)			\
	do {								\
		if (level <= dispatcher_get_debug_level() &&			\
		    net_ratelimit())					\
			pp->debug_packet(pp, skb, ofs, msg);		\
	} while (0)
#else	/* NO DEBUGGING at ALL */
#define DISPATCHER_DBG_BUF(level, msg...)  do {} while (0)
#define DISPATCHER_ERR_BUF(msg...)  do {} while (0)
#define DISPATCHER_DBG(level, msg...)  do {} while (0)
#define DISPATCHER_DBG_RL(msg...)  do {} while (0)
#define DISPATCHER_DBG_PKT(level, pp, skb, ofs, msg)		do {} while (0)
#define DISPATCHER_DBG_RL_PKT(level, pp, skb, ofs, msg)	do {} while (0)
#endif

#define DISPATCHER_BUG() BUG()
#define DISPATCHER_ERR_RL(msg, ...)						\
	do {								\
		if (net_ratelimit())					\
			pr_err(msg, ##__VA_ARGS__);			\
	} while (0)

#ifdef CONFIG_DISPATCHER_DEBUG
#define EnterFunction(level)						\
	do {								\
		if (level <= dispatcher_get_debug_level())			\
			printk(KERN_DEBUG				\
			       pr_fmt("Enter: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)
#define LeaveFunction(level)						\
	do {								\
		if (level <= dispatcher_get_debug_level())			\
			printk(KERN_DEBUG				\
			       pr_fmt("Leave: %s, %s line %i\n"),	\
			       __func__, __FILE__, __LINE__);		\
	} while (0)
#else
#define EnterFunction(level)   do {} while (0)
#define LeaveFunction(level)   do {} while (0)
#endif

#define	DISPATCHER_WAIT_WHILE(expr)	while (expr) { cpu_relax(); }

struct dst_entry;
struct iphdr;
struct sk_buff;

extern struct dispatcher_protocol * dispatcher_proto_get(unsigned short proto);

/*
 *	Extended internal versions of struct dispatcher_service_user and
 *	dispatcher_dest_user for IPv6 support.
 *
 *	We need these to conveniently pass around service and destination
 *	options, but unfortunately, we also need to keep the old definitions to
 *	maintain userspace backwards compatibility for the setsockopt interface.
 */
struct dispatcher_service_user_kern {
	/* virtual service addresses */
	u16			af;
	u16			protocol;
	union nf_inet_addr	addr;		/* virtual ip address */
	u16			port;

	u32			netmask;	/* persistent netmask */
};


struct dispatcher_dest_user_kern {
	/* destination server address */
	union nf_inet_addr	addr;
	u16			port;
};


/*
 *	The information about the virtual service offered to the net
 *	and the forwarding entries
 */
struct dispatcher_service {
	struct list_head	s_list;   /* for normal service table */
	atomic_t		refcnt;   /* reference counter */
	atomic_t		usecnt;   /* use counter */

	u16			af;       /* address family */
	__u16			protocol; /* which protocol (TCP/UDP) */
	union nf_inet_addr	addr;	  /* IP address for virtual service */
	__be16			port;	  /* port number for the service */
	__be32			netmask;  /* grouping granularity */

	struct list_head	destinations;  /* real server d-linked list */
	__u32			num_dests;     /* number of servers */

	struct dispatcher_dest	*dest;

};


/*
 *	The real server destination forwarding entry
 *	with ip address, port number, and so on.
 */
struct dispatcher_dest {
		struct list_head	n_list;   /* for the dests in the service */
		struct list_head	d_list;   /* for table with all the dests */

		u16			af;		/* address family */
		union nf_inet_addr	addr;		/* IP address of the server */
		__be16			port;		/* port number of the server */

		atomic_t		refcnt;		/* reference counter */


		/* for virtual service */
		struct dispatcher_service	*svc;		/* service it belongs to */
		__u16			protocol;	/* which protocol (TCP/UDP) */
		union nf_inet_addr	vaddr;		/* virtual IP address */
		__be16			vport;		/* virtual port number */

		int (*packet_nat)(struct sk_buff *skb, struct dispatcher_service *svc,
			   struct dispatcher_protocol *pp);
};


struct dispatcher_protocol {
	struct dispatcher_protocol	*next;
	char			*name;
	u16			protocol;
	u16			num_states;

	void (*init)(struct dispatcher_protocol *pp);

	void (*exit)(struct dispatcher_protocol *pp);

	int (*snat_handler)(struct sk_buff *skb,
			    struct dispatcher_protocol *pp, struct dispatcher_service *svc);
	struct dispatcher_service *(*get_service)(int af, struct sk_buff *skb,
				struct dispatcher_iphdr *iph);

	int (*dnat_handler)(struct sk_buff *skb,
			    struct dispatcher_protocol *pp, struct dispatcher_service *svc);

	int (*csum_check)(int af, struct sk_buff *skb,
			  struct dispatcher_protocol *pp);

	void (*debug_packet)(struct dispatcher_protocol *pp,
			     const struct sk_buff *skb,
			     int offset,
			     const char *msg);

};

/*
 *      DISPATCHER core functions
 *      (from dispatcher_core.c)
 */
extern const char *dispatcher_proto_name(unsigned proto);

/*
 *	DISPATCHER protocol functions (from dispatcher_proto.c)
 */
extern int dispatcher_protocol_init(void);
extern void dispatcher_protocol_cleanup(void);
extern void
dispatcher_tcpudp_debug_packet(struct dispatcher_protocol *pp, const struct sk_buff *skb,
			  int offset, const char *msg);

extern struct dispatcher_protocol dispatcher_protocol_tcp;

extern const struct ctl_path net_vs_ctl_path[];

extern struct dispatcher_service *
dispatcher_service_get(int af, __u16 protocol, const union nf_inet_addr *vaddr, __be16 vport);

static inline void dispatcher_service_put(struct dispatcher_service *svc)
{
	atomic_dec(&svc->usecnt);
}

static inline void dispatcher_dest_put(struct dispatcher_dest *dest)
{
	atomic_dec(&dest->refcnt);
}

extern struct dispatcher_dest *
dispatcher_lookup_real_service(int af, __u16 protocol,
			  const union nf_inet_addr *daddr, __be16 dport);

extern int dispatcher_use_count_inc(void);
extern void dispatcher_use_count_dec(void);
extern int dispatcher_control_init(void);
extern void dispatcher_control_cleanup(void);
extern struct dispatcher_dest *
dispatcher_find_dest(int af, const union nf_inet_addr *daddr, __be16 dport,
		const union nf_inet_addr *vaddr, __be16 vport, __u16 protocol);
extern struct dispatcher_dest *
dispatcher_get_dest_from_svc(struct dispatcher_service *svc);

/*
 *	Various DISPATCHER packet transmitters (from dispatcher_xmit.c)
 */
extern int dispatcher_nat
(struct sk_buff *skb, struct dispatcher_service *svc, struct dispatcher_protocol *pp);

#ifdef CONFIG_DISPATCHER_IPV6
extern int dispatcher_nat_v6
(struct sk_buff *skb, struct dispatcher_service *svc, struct dispatcher_protocol *pp);
#endif


static inline __wsum dispatcher_check_diff4(__be32 old, __be32 new, __wsum oldsum)
{
	__be32 diff[2] = { ~old, new };

	return csum_partial(diff, sizeof(diff), oldsum);
}

#ifdef CONFIG_DISPATCHER_IPV6
static inline __wsum dispatcher_check_diff16(const __be32 *old, const __be32 *new,
					__wsum oldsum)
{
	__be32 diff[8] = { ~old[3], ~old[2], ~old[1], ~old[0],
			    new[3],  new[2],  new[1],  new[0] };

	return csum_partial(diff, sizeof(diff), oldsum);
}
#endif

static inline __wsum dispatcher_check_diff2(__be16 old, __be16 new, __wsum oldsum)
{
	__be16 diff[2] = { ~old, new };

	return csum_partial(diff, sizeof(diff), oldsum);
}

#endif /* __KERNEL__ */

#endif	/* _NET_DISPATCHER_H */
