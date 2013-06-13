/*
 * DISPATCHER         An implementation of the IP virtual server support for the
 *              LINUX operating system.  DISPATCHER is now implemented as a module
 *              over the NetFilter framework. DISPATCHER can be used to build a
 *              high-performance and highly available server based on a
 *              cluster of servers.
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Peter Kese <peter.kese@ijs.si>
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
#include <linux/init.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/workqueue.h>
#include <linux/swap.h>
#include <linux/seq_file.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/mutex.h>

#include <net/net_namespace.h>
#include <net/ip.h>
#ifdef CONFIG_DISPATCHER_IPV6
#include <net/ipv6.h>
#include <net/ip6_route.h>
#endif
#include <net/route.h>
#include <net/sock.h>
#include <net/genetlink.h>

#include <asm/uaccess.h>

#include "../include/net/dispatcher.h"

/* semaphore for DISPATCHER sockopts. And, [gs]etsockopt may sleep. */
static DEFINE_MUTEX(__dispatcher_mutex);

/* lock for service table */
static DEFINE_RWLOCK(__dispatcher_svc_lock);

/* lock for table with the real services */
static DEFINE_RWLOCK(__dispatcher_rs_lock);

/* number of virtual services */
static int dispatcher_num_services = 0;

#ifdef CONFIG_DISPATCHER_DEBUG
static int sysctl_dispatcher_debug_level = 0;

int dispatcher_get_debug_level(void)
{
	return sysctl_dispatcher_debug_level;
}
#endif

#ifdef CONFIG_DISPATCHER_IPV6
/* Taken from rt6_fill_node() in net/ipv6/route.c, is there a better way? */
static int __dispatcher_addr_is_local_v6(const struct in6_addr *addr)
{
	struct rt6_info *rt;
	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			.ip6_u = {
				.daddr = *addr,
				.saddr = { .s6_addr32 = {0, 0, 0, 0} }, } },
	};

	rt = (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
	if (rt && rt->rt6i_dev && (rt->rt6i_dev->flags & IFF_LOOPBACK))
			return 1;

	return 0;
}
#endif

int
dispatcher_use_count_inc(void)
{
	return try_module_get(THIS_MODULE);
}

void
dispatcher_use_count_dec(void)
{
	module_put(THIS_MODULE);
}


/*
 *	Hash table: for virtual service lookups
 */
#define DISPATCHER_SVC_TAB_BITS 8
#define DISPATCHER_SVC_TAB_SIZE (1 << DISPATCHER_SVC_TAB_BITS)
#define DISPATCHER_SVC_TAB_MASK (DISPATCHER_SVC_TAB_SIZE - 1)

/* the service table hashed by <protocol, addr, port> */
static struct list_head dispatcher_svc_table[DISPATCHER_SVC_TAB_SIZE];

/*
 *	Hash table: for real service lookups
 */
#define DISPATCHER_RTAB_BITS 8
#define DISPATCHER_RTAB_SIZE (1 << DISPATCHER_RTAB_BITS)
#define DISPATCHER_RTAB_MASK (DISPATCHER_RTAB_SIZE - 1)

static struct list_head dispatcher_rtable[DISPATCHER_RTAB_SIZE];

/*
 *	Trash for destinations
 */
static LIST_HEAD(dispatcher_dest_trash);

/*
 *	Returns hash value for virtual service
 */
static __inline__ unsigned
dispatcher_svc_hashkey(int af, unsigned proto, const union nf_inet_addr *addr,
		  __be16 port)
{
	register unsigned porth = ntohs(port);
	__be32 addr_fold = addr->ip;

#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		addr_fold = addr->ip6[0]^addr->ip6[1]^
			    addr->ip6[2]^addr->ip6[3];
#endif

	return (proto^ntohl(addr_fold)^(porth>>DISPATCHER_SVC_TAB_BITS)^porth)
		& DISPATCHER_SVC_TAB_MASK;
}


/*
 *	Hashes a service in the dispatcher_svc_table by <proto,addr,port>.
 *	Should be called with locked tables.
 */
static int dispatcher_svc_hash(struct dispatcher_service *svc)
{
	unsigned hash;

	hash = dispatcher_svc_hashkey(svc->af, svc->protocol, &svc->addr,
				 svc->port);
	list_add(&svc->s_list, &dispatcher_svc_table[hash]);

	/* increase its refcnt because it is referenced by the svc table */
	atomic_inc(&svc->refcnt);
	return 1;
}


/*
 *	Unhashes a service from dispatcher_svc_table/dispatcher_svc_fwm_table.
 *	Should be called with locked tables.
 */
static int dispatcher_svc_unhash(struct dispatcher_service *svc)
{

	/* Remove it from the dispatcher_svc_table table */
	list_del(&svc->s_list);

	atomic_dec(&svc->refcnt);
	return 1;
}


/*
 *	Get service by {proto,addr,port} in the service table.
 */
static inline struct dispatcher_service *
__dispatcher_service_get(int af, __u16 protocol, const union nf_inet_addr *vaddr,
		    __be16 vport)
{
	unsigned hash;
	struct dispatcher_service *svc;

	/* Check for "full" addressed entries */
	hash = dispatcher_svc_hashkey(af, protocol, vaddr, vport);

	list_for_each_entry(svc, &dispatcher_svc_table[hash], s_list){
		if ((svc->af == af)
		    && dispatcher_addr_equal(af, &svc->addr, vaddr)
		    && (svc->port == vport)
		    && (svc->protocol == protocol)) {
			/* HIT */
			atomic_inc(&svc->usecnt);
			return svc;
		}
	}

	return NULL;
}

struct dispatcher_service *
dispatcher_service_get(int af, __u16 protocol,
		  const union nf_inet_addr *vaddr, __be16 vport)
{
	struct dispatcher_service *svc;

	read_lock(&__dispatcher_svc_lock);
	/*
	 *	Check the table hashed by <protocol,addr,port>
	 *	for "full" addressed entries
	 */
	svc = __dispatcher_service_get(af, protocol, vaddr, vport);

	read_unlock(&__dispatcher_svc_lock);

	return svc;
}


static inline void
__dispatcher_bind_svc(struct dispatcher_dest *dest, struct dispatcher_service *svc)
{
	atomic_inc(&svc->refcnt);
	dest->svc = svc;
}

static inline void
__dispatcher_unbind_svc(struct dispatcher_dest *dest)
{
	struct dispatcher_service *svc = dest->svc;

	dest->svc = NULL;
	if (atomic_dec_and_test(&svc->refcnt))
		kfree(svc);
}


/*
 *	Returns hash value for real service
 */
static inline unsigned dispatcher_rs_hashkey(int af,
					    const union nf_inet_addr *addr,
					    __be16 port)
{
	register unsigned porth = ntohs(port);
	__be32 addr_fold = addr->ip;

#ifdef CONFIG_DISPATCHER_IPV6
	if (af == AF_INET6)
		addr_fold = addr->ip6[0]^addr->ip6[1]^
			    addr->ip6[2]^addr->ip6[3];
#endif

	return (ntohl(addr_fold)^(porth>>DISPATCHER_RTAB_BITS)^porth)
		& DISPATCHER_RTAB_MASK;
}

/*
 *	Hashes dispatcher_dest in dispatcher_rtable by <proto,addr,port>.
 *	should be called with locked tables.
 */
static int dispatcher_rs_hash(struct dispatcher_dest *dest)
{
	unsigned hash;

	if (!list_empty(&dest->d_list)) {
		return 0;
	}

	/*
	 *	Hash by proto,addr,port,
	 *	which are the parameters of the real service.
	 */
	hash = dispatcher_rs_hashkey(dest->af, &dest->addr, dest->port);

	list_add(&dest->d_list, &dispatcher_rtable[hash]);

	return 1;
}

/*
 *	UNhashes dispatcher_dest from dispatcher_rtable.
 *	should be called with locked tables.
 */
static int dispatcher_rs_unhash(struct dispatcher_dest *dest)
{
	/*
	 * Remove it from the dispatcher_rtable table.
	 */
	if (!list_empty(&dest->d_list)) {
		list_del(&dest->d_list);
		INIT_LIST_HEAD(&dest->d_list);
	}

	return 1;
}

/*
 *	Lookup real service by <proto,addr,port> in the real service table.
 */
struct dispatcher_dest *
dispatcher_lookup_real_service(int af, __u16 protocol,
			  const union nf_inet_addr *daddr,
			  __be16 dport)
{
	unsigned hash;
	struct dispatcher_dest *dest;

	/*
	 *	Check for "full" addressed entries
	 *	Return the first found entry
	 */
	hash = dispatcher_rs_hashkey(af, daddr, dport);

	read_lock(&__dispatcher_rs_lock);
	list_for_each_entry(dest, &dispatcher_rtable[hash], d_list) {
		if ((dest->af == af)
		    && dispatcher_addr_equal(af, &dest->addr, daddr)
		    && (dest->port == dport)
		    && ((dest->protocol == protocol))) {
			/* HIT */
			read_unlock(&__dispatcher_rs_lock);
			return dest;
		}
	}
	read_unlock(&__dispatcher_rs_lock);

	return NULL;
}

/*
 *	Lookup destination by {addr,port} in the given service
 */
static struct dispatcher_dest *
dispatcher_lookup_dest(struct dispatcher_service *svc, const union nf_inet_addr *daddr,
		  __be16 dport)
{
	struct dispatcher_dest *dest;

	/*
	 * Find the destination for the given service
	 */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if ((dest->af == svc->af)
		    && dispatcher_addr_equal(svc->af, &dest->addr, daddr)
		    && (dest->port == dport)) {
			/* HIT */
			return dest;
		}
	}

	return NULL;
}

struct dispatcher_dest *
dispatcher_get_dest_from_svc(struct dispatcher_service *svc)
{
	atomic_inc(&svc->dest->refcnt);
	return svc->dest;
}

/*
 * Find destination by {daddr,dport,vaddr,protocol}
 * Cretaed to be used in dispatcher_process_message() in
 * the backup synchronization daemon. It finds the
 * destination to be bound to the received connection
 * on the backup.
 *
 * dispatcher_lookup_real_service() looked promissing, but
 * seems not working as expected.
 */
struct dispatcher_dest *
dispatcher_find_dest(int af, const union nf_inet_addr *daddr,
				   __be16 dport,
				   const union nf_inet_addr *vaddr,
				   __be16 vport, __u16 protocol)
{
	struct dispatcher_dest *dest;
	struct dispatcher_service *svc;

	svc = dispatcher_service_get(af, protocol, vaddr, vport);
	if (!svc)
		return NULL;
	dest = dispatcher_lookup_dest(svc, daddr, dport);
	if (dest)
		atomic_inc(&dest->refcnt);
	dispatcher_service_put(svc);
	return dest;
}

/*
 *  Lookup dest by {svc,addr,port} in the destination trash.
 *  The destination trash is used to hold the destinations that are removed
 *  from the service table but are still referenced by some conn entries.
 *  The reason to add the destination trash is when the dest is temporary
 *  down (either by administrator or by monitor program), the dest can be
 *  picked back from the trash, the remaining connections to the dest can
 *  continue, and the counting information of the dest is also useful for
 *  scheduling.
 */
static struct dispatcher_dest *
dispatcher_trash_get_dest(struct dispatcher_service *svc, const union nf_inet_addr *daddr,
		     __be16 dport)
{
	struct dispatcher_dest *dest, *nxt;

	/*
	 * Find the destination in trash
	 */
	list_for_each_entry_safe(dest, nxt, &dispatcher_dest_trash, n_list) {
		if (dest->af == svc->af &&
		    dispatcher_addr_equal(svc->af, &dest->addr, daddr) &&
		    dest->port == dport &&
		    dest->protocol == svc->protocol &&
		    ((dispatcher_addr_equal(svc->af, &dest->vaddr, &svc->addr) &&
		      dest->vport == svc->port))) {
			/* HIT */
			return dest;
		}

		/*
		 * Try to purge the destination from trash if not referenced
		 */
		if (atomic_read(&dest->refcnt) == 1) {
			list_del(&dest->n_list);
			__dispatcher_unbind_svc(dest);
			kfree(dest);
		}
	}

	return NULL;
}


/*
 *  Clean up all the destinations in the trash
 *  Called by the dispatcher_control_cleanup()
 *
 *  When the dispatcher_control_clearup is activated by dispatcher module exit,
 *  the service tables must have been flushed and all the connections
 *  are expired, and the refcnt of each destination in the trash must
 *  be 1, so we simply release them here.
 */
static void dispatcher_trash_cleanup(void)
{
	struct dispatcher_dest *dest, *nxt;

	list_for_each_entry_safe(dest, nxt, &dispatcher_dest_trash, n_list) {
		list_del(&dest->n_list);
		__dispatcher_unbind_svc(dest);
		kfree(dest);
	}
}

/*
 *	Update a destination in the given service
 */
static void
__dispatcher_update_dest(struct dispatcher_service *svc,
		    struct dispatcher_dest *dest, struct dispatcher_dest_user_kern *udest)
{

	write_lock_bh(&__dispatcher_rs_lock);
	dispatcher_rs_hash(dest);
	write_unlock_bh(&__dispatcher_rs_lock);
	/* bind the service */
	if (!dest->svc) {
		__dispatcher_bind_svc(dest, svc);
	} else {
		if (dest->svc != svc) {
			__dispatcher_unbind_svc(dest);
			__dispatcher_bind_svc(dest, svc);
		}
	}
}


/*
 *	Create a destination for the given service
 */
static int
dispatcher_new_dest(struct dispatcher_service *svc, struct dispatcher_dest_user_kern *udest,
	       struct dispatcher_dest **dest_p)
{
	struct dispatcher_dest *dest;
	unsigned atype;

	EnterFunction(2);

#ifdef CONFIG_DISPATCHER_IPV6
	if (svc->af == AF_INET6) {
		atype = ipv6_addr_type(&udest->addr.in6);
		if ((!(atype & IPV6_ADDR_UNICAST) ||
			atype & IPV6_ADDR_LINKLOCAL) &&
			!__dispatcher_addr_is_local_v6(&udest->addr.in6))
			return -EINVAL;
	} else
#endif
	{
		atype = inet_addr_type(&init_net, udest->addr.ip);
		if (atype != RTN_LOCAL && atype != RTN_UNICAST)
			return -EINVAL;
	}

	dest = kzalloc(sizeof(struct dispatcher_dest), GFP_ATOMIC);
	if (dest == NULL) {
		pr_err("%s(): no memory.\n", __func__);
		return -ENOMEM;
	}

	dest->af = svc->af;
	dest->protocol = svc->protocol;
	dest->vaddr = svc->addr;
	dest->vport = svc->port;
	dispatcher_addr_copy(svc->af, &dest->addr, &udest->addr);
	dest->port = udest->port;
#ifdef CONFIG_DISPATCHER_IPV6
	if (svc->af == AF_INET6) {
		dest->packet_nat = dispatcher_nat_v6;
	} else
#endif
	{
		dest->packet_nat = dispatcher_nat;
	}
	atomic_set(&dest->refcnt, 0);

	INIT_LIST_HEAD(&dest->d_list);
	__dispatcher_update_dest(svc, dest, udest);

	*dest_p = dest;

	LeaveFunction(2);
	return 0;
}


/*
 *	Add a destination into an existing service
 */
static int
dispatcher_add_dest(struct dispatcher_service *svc, struct dispatcher_dest_user_kern *udest)
{
	struct dispatcher_dest *dest;
	union nf_inet_addr daddr;
	__be16 dport = udest->port;
	int ret;

	EnterFunction(2);

	dispatcher_addr_copy(svc->af, &daddr, &udest->addr);

	/*
	 * Check if the dest already exists in the list
	 */
	dest = dispatcher_lookup_dest(svc, &daddr, dport);

	if (dest != NULL) {
		DISPATCHER_DBG(1, "%s(): dest already exists\n", __func__);
		return -EEXIST;
	}

	/*
	 * Check if the dest already exists in the trash and
	 * is from the same service
	 */
	dest = dispatcher_trash_get_dest(svc, &daddr, dport);

	if (dest != NULL) {

		__dispatcher_update_dest(svc, dest, udest);

		/*
		 * Get the destination from the trash
		 */
		list_del(&dest->n_list);

		write_lock_bh(&__dispatcher_svc_lock);

		/*
		 * Wait until all other svc users go away.
		 */
		DISPATCHER_WAIT_WHILE(atomic_read(&svc->usecnt) > 1);

		list_add(&dest->n_list, &svc->destinations);
		svc->num_dests++;
		svc->dest = dest;

		write_unlock_bh(&__dispatcher_svc_lock);
		return 0;
	}

	/*
	 * Allocate and initialize the dest structure
	 */
	ret = dispatcher_new_dest(svc, udest, &dest);
	if (ret) {
		return ret;
	}

	/*
	 * Add the dest entry into the list
	 */
	atomic_inc(&dest->refcnt);

	write_lock_bh(&__dispatcher_svc_lock);

	/*
	 * Wait until all other svc users go away.
	 */
	DISPATCHER_WAIT_WHILE(atomic_read(&svc->usecnt) > 1);

	list_add(&dest->n_list, &svc->destinations);
	svc->num_dests++;
	svc->dest = dest;

	write_unlock_bh(&__dispatcher_svc_lock);

	LeaveFunction(2);

	return 0;
}

/*
 *	Delete a destination (must be already unlinked from the service)
 */
static void __dispatcher_del_dest(struct dispatcher_dest *dest)
{

	/*
	 *  Remove it from the d-linked list with the real services.
	 */
	write_lock_bh(&__dispatcher_rs_lock);
	dispatcher_rs_unhash(dest);
	write_unlock_bh(&__dispatcher_rs_lock);

	/*
	 *  Decrease the refcnt of the dest, and free the dest
	 *  if nobody refers to it (refcnt=0). Otherwise, throw
	 *  the destination into the trash.
	 */
	if (atomic_dec_and_test(&dest->refcnt)) {
		/* simply decrease svc->refcnt here, let the caller check
		   and release the service if nobody refers to it.
		   Only user context can release destination and service,
		   and only one user context can update virtual service at a
		   time, so the operation here is OK */
		atomic_dec(&dest->svc->refcnt);
		kfree(dest);
	} else {
		DISPATCHER_DBG_BUF(3, "Moving dest %s:%u into trash, "
			      "dest->refcnt=%d\n",
			      DISPATCHER_DBG_ADDR(dest->af, &dest->addr),
			      ntohs(dest->port),
			      atomic_read(&dest->refcnt));
		list_add(&dest->n_list, &dispatcher_dest_trash);
		atomic_inc(&dest->refcnt);
	}
}


/*
 *	Unlink a destination from the given service
 */
static void __dispatcher_unlink_dest(struct dispatcher_service *svc,
				struct dispatcher_dest *dest,
				int svcupd)
{
	/*
	 *  Remove it from the d-linked destination list.
	 */
	list_del(&dest->n_list);
	svc->num_dests--;
}


/*
 *	Delete a destination server in the given service
 */
static int
dispatcher_del_dest(struct dispatcher_service *svc, struct dispatcher_dest_user_kern *udest)
{
	struct dispatcher_dest *dest;
	__be16 dport = udest->port;

	EnterFunction(2);

	dest = dispatcher_lookup_dest(svc, &udest->addr, dport);

	if (dest == NULL) {
		DISPATCHER_DBG(1, "%s(): destination not found!\n", __func__);
		return -ENOENT;
	}

	write_lock_bh(&__dispatcher_svc_lock);

	/*
	 *	Wait until all other svc users go away.
	 */
	DISPATCHER_WAIT_WHILE(atomic_read(&svc->usecnt) > 1);

	/*
	 *	Unlink dest from the service
	 */
	__dispatcher_unlink_dest(svc, dest, 1);

	write_unlock_bh(&__dispatcher_svc_lock);

	/*
	 *	Delete the destination
	 */
	__dispatcher_del_dest(dest);

	LeaveFunction(2);

	return 0;
}


/*
 *	Add a service into the service hash table
 */
static int
dispatcher_add_service(struct dispatcher_service_user_kern *u,
		  struct dispatcher_service **svc_p)
{
	int ret = 0;
	struct dispatcher_service *svc = NULL;

	/* increase the module use count */
	dispatcher_use_count_inc();

#ifdef CONFIG_DISPATCHER_IPV6
	if (u->af == AF_INET6 && (u->netmask < 1 || u->netmask > 128)) {
		ret = -EINVAL;
		goto out_err;
	}
#endif

	svc = kzalloc(sizeof(struct dispatcher_service), GFP_ATOMIC);
	if (svc == NULL) {
		DISPATCHER_DBG(1, "%s(): no memory\n", __func__);
		ret = -ENOMEM;
		goto out_err;
	}

	/* I'm the first user of the service */
	atomic_set(&svc->usecnt, 1);
	atomic_set(&svc->refcnt, 0);

	svc->af = u->af;
	svc->protocol = u->protocol;
	dispatcher_addr_copy(svc->af, &svc->addr, &u->addr);
	svc->port = u->port;
	svc->netmask = u->netmask;

	INIT_LIST_HEAD(&svc->destinations);

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		dispatcher_num_services++;

	/* Hash the service into the service table */
	write_lock_bh(&__dispatcher_svc_lock);
	dispatcher_svc_hash(svc);
	write_unlock_bh(&__dispatcher_svc_lock);

	*svc_p = svc;
	return 0;

  out_err:
	if (svc != NULL) {
		kfree(svc);
	}

	/* decrease the module use count */
	dispatcher_use_count_dec();

	return ret;
}


/*
 *	Delete a service from the service list
 *	- The service must be unlinked, unlocked and not referenced!
 *	- We are called under _bh lock
 */
static void __dispatcher_del_service(struct dispatcher_service *svc)
{
	struct dispatcher_dest *dest, *nxt;

	/* Count only IPv4 services for old get/setsockopt interface */
	if (svc->af == AF_INET)
		dispatcher_num_services--;

	/*
	 *    Unlink the whole destination list
	 */
	list_for_each_entry_safe(dest, nxt, &svc->destinations, n_list) {
		__dispatcher_unlink_dest(svc, dest, 0);
		__dispatcher_del_dest(dest);
	}

	/*
	 *    Free the service if nobody refers to it
	 */
	if (atomic_read(&svc->refcnt) == 0)
		kfree(svc);

	/* decrease the module use count */
	dispatcher_use_count_dec();
}

/*
 *	Delete a service from the service list
 */
static int dispatcher_del_service(struct dispatcher_service *svc)
{
	if (svc == NULL)
		return -EEXIST;

	/*
	 * Unhash it from the service table
	 */
	write_lock_bh(&__dispatcher_svc_lock);

	dispatcher_svc_unhash(svc);

	/*
	 * Wait until all the svc users go away.
	 */
	DISPATCHER_WAIT_WHILE(atomic_read(&svc->usecnt) > 1);

	__dispatcher_del_service(svc);

	write_unlock_bh(&__dispatcher_svc_lock);

	return 0;
}


/*
 *	Flush all the virtual services
 */
static int dispatcher_flush(void)
{
	int idx;
	struct dispatcher_service *svc, *nxt;

	/*
	 * Flush the service table hashed by <protocol,addr,port>
	 */
	for(idx = 0; idx < DISPATCHER_SVC_TAB_SIZE; idx++) {
		list_for_each_entry_safe(svc, nxt, &dispatcher_svc_table[idx], s_list) {
			write_lock_bh(&__dispatcher_svc_lock);
			dispatcher_svc_unhash(svc);
			/*
			 * Wait until all the svc users go away.
			 */
			DISPATCHER_WAIT_WHILE(atomic_read(&svc->usecnt) > 0);
			__dispatcher_del_service(svc);
			write_unlock_bh(&__dispatcher_svc_lock);
		}
	}

	return 0;
}

/*
 *	DISPATCHER sysctl table (under the /proc/sys/net/ipv4/vs/)
 */

static struct ctl_table vs_vars[] = {
#ifdef CONFIG_DISPATCHER_DEBUG
	{
		.procname	= "debug_level",
		.data		= &sysctl_dispatcher_debug_level,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{ .ctl_name = 0 }
};

const struct ctl_path net_vs_ctl_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET, },
	{ .procname = "ipv4", .ctl_name = NET_IPV4, },
	{ .procname = "vs", },
	{ }
};
EXPORT_SYMBOL_GPL(net_vs_ctl_path);

static struct ctl_table_header * sysctl_header;

#ifdef CONFIG_PROC_FS

struct dispatcher_iter {
	struct list_head *table;
	int bucket;
};

/* Get the Nth entry in the two lists */
static struct dispatcher_service *dispatcher_info_array(struct seq_file *seq, loff_t pos)
{
	struct dispatcher_iter *iter = seq->private;
	int idx;
	struct dispatcher_service *svc;

	/* look in hash by protocol */
	for (idx = 0; idx < DISPATCHER_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &dispatcher_svc_table[idx], s_list) {
			if (pos-- == 0){
				iter->table = dispatcher_svc_table;
				iter->bucket = idx;
				return svc;
			}
		}
	}
	return NULL;
}

static void *dispatcher_info_seq_start(struct seq_file *seq, loff_t *pos)
__acquires(__dispatcher_svc_lock)
{

	read_lock_bh(&__dispatcher_svc_lock);
	return *pos ? dispatcher_info_array(seq, *pos - 1) : SEQ_START_TOKEN;
}


static void *dispatcher_info_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct list_head *e;
	struct dispatcher_iter *iter;
	struct dispatcher_service *svc;

	++*pos;
	if (v == SEQ_START_TOKEN)
		return dispatcher_info_array(seq,0);

	svc = v;
	iter = seq->private;

	if (iter->table == dispatcher_svc_table) {
		/* next service in table hashed by protocol */
		if ((e = svc->s_list.next) != &dispatcher_svc_table[iter->bucket])
			return list_entry(e, struct dispatcher_service, s_list);


		while (++iter->bucket < DISPATCHER_SVC_TAB_SIZE) {
			list_for_each_entry(svc,&dispatcher_svc_table[iter->bucket],
					    s_list) {
				return svc;
			}
		}
	}
	return NULL;
}

static void dispatcher_info_seq_stop(struct seq_file *seq, void *v)
__releases(__dispatcher_svc_lock)
{
	read_unlock_bh(&__dispatcher_svc_lock);
}


static int dispatcher_info_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq,
			 "Prot LocalAddress:Port \n");
		seq_puts(seq,
			 "  -> RemoteAddress:Port \n");
	} else {
		const struct dispatcher_service *svc = v;
		const struct dispatcher_iter *iter = seq->private;
		const struct dispatcher_dest *dest;

		if (iter->table == dispatcher_svc_table) {
#ifdef CONFIG_DISPATCHER_IPV6
			if (svc->af == AF_INET6)
				seq_printf(seq, "%s  [%pI6]:%04X",
					   dispatcher_proto_name(svc->protocol),
					   &svc->addr.in6,
					   ntohs(svc->port));
			else
#endif
				seq_printf(seq, "%s  %08X:%04X ",
					   dispatcher_proto_name(svc->protocol),
					   ntohl(svc->addr.ip),
					   ntohs(svc->port));
		}

		seq_putc(seq, '\n');

		list_for_each_entry(dest, &svc->destinations, n_list) {
#ifdef CONFIG_DISPATCHER_IPV6
			if (dest->af == AF_INET6)
				seq_printf(seq,
					   "  -> [%pI6]:%04X\n",
					   &dest->addr.in6,
					   ntohs(dest->port));
			else
#endif
				seq_printf(seq,
					   "  -> %08X:%04X\n",
					   ntohl(dest->addr.ip),
					   ntohs(dest->port));

		}
	}
	return 0;
}

static const struct seq_operations dispatcher_info_seq_ops = {
	.start = dispatcher_info_seq_start,
	.next  = dispatcher_info_seq_next,
	.stop  = dispatcher_info_seq_stop,
	.show  = dispatcher_info_seq_show,
};

static int dispatcher_info_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &dispatcher_info_seq_ops,
			sizeof(struct dispatcher_iter));
}

static const struct file_operations dispatcher_info_fops = {
	.owner	 = THIS_MODULE,
	.open    = dispatcher_info_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

#endif

#define SET_CMDID(cmd)		(cmd - DISPATCHER_BASE_CTL)
#define SERVICE_ARG_LEN		(sizeof(struct dispatcher_service_user))
#define SVCDEST_ARG_LEN		(sizeof(struct dispatcher_service_user) +	\
				 sizeof(struct dispatcher_dest_user))
#define MAX_ARG_LEN		SVCDEST_ARG_LEN

static const unsigned char set_arglen[SET_CMDID(DISPATCHER_SO_SET_MAX)+1] = {
	[SET_CMDID(DISPATCHER_SO_SET_ADD)]		= SERVICE_ARG_LEN,
	[SET_CMDID(DISPATCHER_SO_SET_DEL)]		= SERVICE_ARG_LEN,
	[SET_CMDID(DISPATCHER_SO_SET_FLUSH)]		= 0,
	[SET_CMDID(DISPATCHER_SO_SET_ADDDEST)]	= SVCDEST_ARG_LEN,
	[SET_CMDID(DISPATCHER_SO_SET_DELDEST)]	= SVCDEST_ARG_LEN,
};

static void dispatcher_copy_usvc_compat(struct dispatcher_service_user_kern *usvc,
				  struct dispatcher_service_user *usvc_compat)
{
	usvc->af		= AF_INET;
	usvc->protocol		= usvc_compat->protocol;
	usvc->addr.ip		= usvc_compat->addr;
	usvc->port		= usvc_compat->port;
	usvc->netmask		= usvc_compat->netmask;
}

static void dispatcher_copy_udest_compat(struct dispatcher_dest_user_kern *udest,
				   struct dispatcher_dest_user *udest_compat)
{
	udest->addr.ip		= udest_compat->addr;
	udest->port		= udest_compat->port;
}

static int
do_dispatcher_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	int ret;
	unsigned char arg[MAX_ARG_LEN];
	struct dispatcher_service_user *usvc_compat;
	struct dispatcher_service_user_kern usvc;
	struct dispatcher_service *svc;
	struct dispatcher_dest_user *udest_compat;
	struct dispatcher_dest_user_kern udest;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (len != set_arglen[SET_CMDID(cmd)]) {
		pr_err("set_ctl: len %u != %u\n",
		       len, set_arglen[SET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (copy_from_user(arg, user, len) != 0)
		return -EFAULT;

	/* increase the module use count */
	dispatcher_use_count_inc();

	if (mutex_lock_interruptible(&__dispatcher_mutex)) {
		ret = -ERESTARTSYS;
		goto out_dec;
	}

	if (cmd == DISPATCHER_SO_SET_FLUSH) {
		/* Flush the virtual service */
		ret = dispatcher_flush();
		goto out_unlock;
	}

	usvc_compat = (struct dispatcher_service_user *)arg;
	udest_compat = (struct dispatcher_dest_user *)(usvc_compat + 1);

	/* We only use the new structs internally, so copy userspace compat
	 * structs to extended internal versions */
	dispatcher_copy_usvc_compat(&usvc, usvc_compat);
	dispatcher_copy_udest_compat(&udest, udest_compat);

	/* Check for valid protocol: TCP or UDP */
	if (usvc.protocol != IPPROTO_TCP && usvc.protocol != IPPROTO_UDP) {
		pr_err("set_ctl: invalid protocol: %d %pI4:%d\n",
		       usvc.protocol, &usvc.addr.ip,
		       ntohs(usvc.port));
		ret = -EFAULT;
		goto out_unlock;
	}

	/* Lookup the exact service by <protocol, addr, port> */
	svc = __dispatcher_service_get(usvc.af, usvc.protocol,
				  &usvc.addr, usvc.port);

	if (cmd != DISPATCHER_SO_SET_ADD
	    && (svc == NULL || svc->protocol != usvc.protocol)) {
		ret = -ESRCH;
		goto out_unlock;
	}

	switch (cmd) {
	case DISPATCHER_SO_SET_ADD:
		if (svc != NULL)
			ret = -EEXIST;
		else
			ret = dispatcher_add_service(&usvc, &svc);
		break;
	case DISPATCHER_SO_SET_DEL:
		ret = dispatcher_del_service(svc);
		if (!ret)
			goto out_unlock;
		break;
	case DISPATCHER_SO_SET_ADDDEST:
		ret = dispatcher_add_dest(svc, &udest);
		break;
	case DISPATCHER_SO_SET_DELDEST:
		ret = dispatcher_del_dest(svc, &udest);
		break;
	default:
		ret = -EINVAL;
	}

	if (svc)
		dispatcher_service_put(svc);

  out_unlock:
	mutex_unlock(&__dispatcher_mutex);
  out_dec:
	/* decrease the module use count */
	dispatcher_use_count_dec();

	return ret;
}

static void
dispatcher_copy_service(struct dispatcher_service_entry *dst, struct dispatcher_service *src)
{
	dst->protocol = src->protocol;
	dst->addr = src->addr.ip;
	dst->port = src->port;
	dst->netmask = src->netmask;
	dst->num_dests = src->num_dests;
}

static inline int
__dispatcher_get_service_entries(const struct dispatcher_get_services *get,
			    struct dispatcher_get_services __user *uptr)
{
	int idx, count=0;
	struct dispatcher_service *svc;
	struct dispatcher_service_entry entry;
	int ret = 0;

	for (idx = 0; idx < DISPATCHER_SVC_TAB_SIZE; idx++) {
		list_for_each_entry(svc, &dispatcher_svc_table[idx], s_list) {
			/* Only expose IPv4 entries to old interface */
			if (svc->af != AF_INET)
				continue;

			if (count >= get->num_services)
				goto out;
			memset(&entry, 0, sizeof(entry));
			dispatcher_copy_service(&entry, svc);
			if (copy_to_user(&uptr->entrytable[count],
					 &entry, sizeof(entry))) {
				ret = -EFAULT;
				goto out;
			}
			count++;
		}
	}
  out:
	return ret;
}

static inline int
__dispatcher_get_dest_entries(const struct dispatcher_get_dests *get,
			 struct dispatcher_get_dests __user *uptr)
{
	struct dispatcher_service *svc;
	union nf_inet_addr addr = { .ip = get->addr };
	int ret = 0;

	svc = __dispatcher_service_get(AF_INET, get->protocol, &addr,
					  get->port);

	if (svc) {
		int count = 0;
		struct dispatcher_dest *dest;
		struct dispatcher_dest_entry entry;

		list_for_each_entry(dest, &svc->destinations, n_list) {
			if (count >= get->num_dests)
				break;

			entry.addr = dest->addr.ip;
			entry.port = dest->port;
			if (copy_to_user(&uptr->entrytable[count],
					 &entry, sizeof(entry))) {
				ret = -EFAULT;
				break;
			}
			count++;
		}
		dispatcher_service_put(svc);
	} else
		ret = -ESRCH;
	return ret;
}

#define GET_CMDID(cmd)		(cmd - DISPATCHER_BASE_CTL)
#define GET_INFO_ARG_LEN	(sizeof(struct dispatcher_getinfo))
#define GET_SERVICES_ARG_LEN	(sizeof(struct dispatcher_get_services))
#define GET_SERVICE_ARG_LEN	(sizeof(struct dispatcher_service_entry))
#define GET_DESTS_ARG_LEN	(sizeof(struct dispatcher_get_dests))

static const unsigned char get_arglen[GET_CMDID(DISPATCHER_SO_GET_MAX)+1] = {
	[GET_CMDID(DISPATCHER_SO_GET_VERSION)]	= 64,
	[GET_CMDID(DISPATCHER_SO_GET_INFO)]		= GET_INFO_ARG_LEN,
	[GET_CMDID(DISPATCHER_SO_GET_SERVICES)]	= GET_SERVICES_ARG_LEN,
	[GET_CMDID(DISPATCHER_SO_GET_SERVICE)]	= GET_SERVICE_ARG_LEN,
	[GET_CMDID(DISPATCHER_SO_GET_DESTS)]		= GET_DESTS_ARG_LEN,
};

static int
do_dispatcher_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	unsigned char arg[128];
	int ret = 0;
	pr_err("yeah\n");

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (*len < get_arglen[GET_CMDID(cmd)]) {
		pr_err("get_ctl: len %u < %u\n",
		       *len, get_arglen[GET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (copy_from_user(arg, user, get_arglen[GET_CMDID(cmd)]) != 0)
		return -EFAULT;

	if (mutex_lock_interruptible(&__dispatcher_mutex))
		return -ERESTARTSYS;

	switch (cmd) {
	case DISPATCHER_SO_GET_VERSION:
	{
		char buf[64];

		if (copy_to_user(user, buf, strlen(buf)+1) != 0) {
			ret = -EFAULT;
			goto out;
		}
		*len = strlen(buf)+1;
	}
	break;

	case DISPATCHER_SO_GET_INFO:
	{
		struct dispatcher_getinfo info;
		info.version = DISPATCHER_VERSION_CODE;
		info.num_services = dispatcher_num_services;
		if (copy_to_user(user, &info, sizeof(info)) != 0)
			ret = -EFAULT;
	}
	break;

	case DISPATCHER_SO_GET_SERVICES:
	{
		struct dispatcher_get_services *get;
		int size;

		get = (struct dispatcher_get_services *)arg;
		size = sizeof(*get) +
			sizeof(struct dispatcher_service_entry) * get->num_services;
		if (*len != size) {
			pr_err("length: %u != %u\n", *len, size);
			ret = -EINVAL;
			goto out;
		}
		ret = __dispatcher_get_service_entries(get, user);
	}
	break;

	case DISPATCHER_SO_GET_SERVICE:
	{
		struct dispatcher_service_entry *entry;
		struct dispatcher_service *svc;
		union nf_inet_addr addr;

		entry = (struct dispatcher_service_entry *)arg;
		addr.ip = entry->addr;
		svc = __dispatcher_service_get(AF_INET, entry->protocol,
						  &addr, entry->port);
		if (svc) {
			dispatcher_copy_service(entry, svc);
			if (copy_to_user(user, entry, sizeof(*entry)) != 0)
				ret = -EFAULT;
			dispatcher_service_put(svc);
		} else
			ret = -ESRCH;
	}
	break;

	case DISPATCHER_SO_GET_DESTS:
	{
		struct dispatcher_get_dests *get;
		int size;

		get = (struct dispatcher_get_dests *)arg;
		size = sizeof(*get) +
			sizeof(struct dispatcher_dest_entry) * get->num_dests;
		if (*len != size) {
			pr_err("length: %u != %u\n", *len, size);
			ret = -EINVAL;
			goto out;
		}
		ret = __dispatcher_get_dest_entries(get, user);
	}
	break;

	default:
		ret = -EINVAL;
	}

  out:
	mutex_unlock(&__dispatcher_mutex);
	return ret;
}


static struct nf_sockopt_ops dispatcher_sockopts = {
	.pf		= PF_INET,
	.set_optmin	= DISPATCHER_BASE_CTL,
	.set_optmax	= DISPATCHER_SO_SET_MAX+1,
	.set		= do_dispatcher_set_ctl,
	.get_optmin	= DISPATCHER_BASE_CTL,
	.get_optmax	= DISPATCHER_SO_GET_MAX+1,
	.get		= do_dispatcher_get_ctl,
	.owner		= THIS_MODULE,
};

/*
 * Generic Netlink interface
 */

/* DISPATCHER genetlink family */
static struct genl_family dispatcher_genl_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= DISPATCHER_GENL_NAME,
	.version	= DISPATCHER_GENL_VERSION,
	.maxattr	= DISPATCHER_CMD_MAX,
};

/* Policy used for first-level command attributes */
static const struct nla_policy dispatcher_cmd_policy[DISPATCHER_CMD_ATTR_MAX + 1] = {
	[DISPATCHER_CMD_ATTR_SERVICE]		= { .type = NLA_NESTED },
	[DISPATCHER_CMD_ATTR_DEST]		= { .type = NLA_NESTED },
};

/* Policy used for attributes in nested attribute DISPATCHER_CMD_ATTR_SERVICE */
static const struct nla_policy dispatcher_svc_policy[DISPATCHER_SVC_ATTR_MAX + 1] = {
	[DISPATCHER_SVC_ATTR_AF]		= { .type = NLA_U16 },
	[DISPATCHER_SVC_ATTR_PROTOCOL]	= { .type = NLA_U16 },
	[DISPATCHER_SVC_ATTR_ADDR]		= { .type = NLA_BINARY,
					    .len = sizeof(union nf_inet_addr) },
	[DISPATCHER_SVC_ATTR_PORT]		= { .type = NLA_U16 },
	[DISPATCHER_SVC_ATTR_NETMASK]		= { .type = NLA_U32 },
};

/* Policy used for attributes in nested attribute DISPATCHER_CMD_ATTR_DEST */
static const struct nla_policy dispatcher_dest_policy[DISPATCHER_DEST_ATTR_MAX + 1] = {
	[DISPATCHER_DEST_ATTR_ADDR]		= { .type = NLA_BINARY,
					    .len = sizeof(union nf_inet_addr) },
	[DISPATCHER_DEST_ATTR_PORT]		= { .type = NLA_U16 },
};

static int dispatcher_genl_fill_service(struct sk_buff *skb,
				   struct dispatcher_service *svc)
{
/*
	struct nlattr *nl_service;

	nl_service = nla_nest_start(skb, DISPATCHER_CMD_ATTR_SERVICE);
	if (!nl_service)
		return -EMSGSIZE;

	NLA_PUT_U16(skb, DISPATCHER_SVC_ATTR_AF, svc->af);

	NLA_PUT_U16(skb, DISPATCHER_SVC_ATTR_PROTOCOL, svc->protocol);
	NLA_PUT(skb, DISPATCHER_SVC_ATTR_ADDR, sizeof(svc->addr), &svc->addr);
	NLA_PUT_U16(skb, DISPATCHER_SVC_ATTR_PORT, svc->port);

	NLA_PUT_U32(skb, DISPATCHER_SVC_ATTR_NETMASK, svc->netmask);


	nla_nest_end(skb, nl_service);
*/
	return 0;
}

static int dispatcher_genl_dump_service(struct sk_buff *skb,
				   struct dispatcher_service *svc,
				   struct netlink_callback *cb)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &dispatcher_genl_family, NLM_F_MULTI,
			  DISPATCHER_CMD_NEW_SERVICE);
	if (!hdr)
		return -EMSGSIZE;

	if (dispatcher_genl_fill_service(skb, svc) < 0)
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int dispatcher_genl_dump_services(struct sk_buff *skb,
				    struct netlink_callback *cb)
{
	int idx = 0, i;
	int start = cb->args[0];
	struct dispatcher_service *svc;

	mutex_lock(&__dispatcher_mutex);
	for (i = 0; i < DISPATCHER_SVC_TAB_SIZE; i++) {
		list_for_each_entry(svc, &dispatcher_svc_table[i], s_list) {
			if (++idx <= start)
				continue;
			if (dispatcher_genl_dump_service(skb, svc, cb) < 0) {
				idx--;
				goto nla_put_failure;
			}
		}
	}

nla_put_failure:
	mutex_unlock(&__dispatcher_mutex);
	cb->args[0] = idx;

	return skb->len;
}

static int dispatcher_genl_parse_service(struct dispatcher_service_user_kern *usvc,
				    struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[DISPATCHER_SVC_ATTR_MAX + 1];
	struct nlattr *nla_af, *nla_port, *nla_protocol, *nla_addr;

	/* Parse mandatory identifying service fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, DISPATCHER_SVC_ATTR_MAX, nla, dispatcher_svc_policy))
		return -EINVAL;

	nla_af		= attrs[DISPATCHER_SVC_ATTR_AF];
	nla_protocol	= attrs[DISPATCHER_SVC_ATTR_PROTOCOL];
	nla_addr	= attrs[DISPATCHER_SVC_ATTR_ADDR];
	nla_port	= attrs[DISPATCHER_SVC_ATTR_PORT];

	if (!(nla_af && (nla_port && nla_protocol && nla_addr)))
		return -EINVAL;

	memset(usvc, 0, sizeof(*usvc));

	usvc->af = nla_get_u16(nla_af);
#ifdef CONFIG_DISPATCHER_IPV6
	if (usvc->af != AF_INET && usvc->af != AF_INET6)
#else
	if (usvc->af != AF_INET)
#endif
		return -EAFNOSUPPORT;

	usvc->protocol = nla_get_u16(nla_protocol);
	nla_memcpy(&usvc->addr, nla_addr, sizeof(usvc->addr));
	usvc->port = nla_get_u16(nla_port);

	/* If a full entry was requested, check for the additional fields */
	if (full_entry) {
		struct nlattr *nla_netmask;
		struct dispatcher_service *svc;

		nla_netmask = attrs[DISPATCHER_SVC_ATTR_NETMASK];

		if (!(nla_netmask))
			return -EINVAL;

		/* prefill flags from service if it already exists */
		svc = __dispatcher_service_get(usvc->af, usvc->protocol,
						  &usvc->addr, usvc->port);
		usvc->netmask = nla_get_u32(nla_netmask);
	}

	return 0;
}

static struct dispatcher_service *dispatcher_genl_find_service(struct nlattr *nla)
{
	struct dispatcher_service_user_kern usvc;
	int ret;

	ret = dispatcher_genl_parse_service(&usvc, nla, 0);
	if (ret)
		return ERR_PTR(ret);

	return __dispatcher_service_get(usvc.af, usvc.protocol,
					   &usvc.addr, usvc.port);
}

static int dispatcher_genl_fill_dest(struct sk_buff *skb, struct dispatcher_dest *dest)
{
/*
	struct nlattr *nl_dest;

	nl_dest = nla_nest_start(skb, DISPATCHER_CMD_ATTR_DEST);
	if (!nl_dest)
		return -EMSGSIZE;

	NLA_PUT(skb, DISPATCHER_DEST_ATTR_ADDR, sizeof(dest->addr), &dest->addr);
	NLA_PUT_U16(skb, DISPATCHER_DEST_ATTR_PORT, dest->port);

	nla_nest_end(skb, nl_dest);
*/
	return 0;
}

static int dispatcher_genl_dump_dest(struct sk_buff *skb, struct dispatcher_dest *dest,
				struct netlink_callback *cb)
{
	void *hdr;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			  &dispatcher_genl_family, NLM_F_MULTI,
			  DISPATCHER_CMD_NEW_DEST);
	if (!hdr)
		return -EMSGSIZE;

	if (dispatcher_genl_fill_dest(skb, dest) < 0)
		goto nla_put_failure;

	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int dispatcher_genl_dump_dests(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	int idx = 0;
	int start = cb->args[0];
	struct dispatcher_service *svc;
	struct dispatcher_dest *dest;
	struct nlattr *attrs[DISPATCHER_CMD_ATTR_MAX + 1];

	mutex_lock(&__dispatcher_mutex);

	/* Try to find the service for which to dump destinations */
	if (nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs,
			DISPATCHER_CMD_ATTR_MAX, dispatcher_cmd_policy))
		goto out_err;

	svc = dispatcher_genl_find_service(attrs[DISPATCHER_CMD_ATTR_SERVICE]);
	if (IS_ERR(svc) || svc == NULL)
		goto out_err;

	/* Dump the destinations */
	list_for_each_entry(dest, &svc->destinations, n_list) {
		if (++idx <= start)
			continue;
		if (dispatcher_genl_dump_dest(skb, dest, cb) < 0) {
			idx--;
			goto nla_put_failure;
		}
	}

nla_put_failure:
	cb->args[0] = idx;
	dispatcher_service_put(svc);

out_err:
	mutex_unlock(&__dispatcher_mutex);

	return skb->len;
}

static int dispatcher_genl_parse_dest(struct dispatcher_dest_user_kern *udest,
				 struct nlattr *nla, int full_entry)
{
	struct nlattr *attrs[DISPATCHER_DEST_ATTR_MAX + 1];
	struct nlattr *nla_addr, *nla_port;

	/* Parse mandatory identifying destination fields first */
	if (nla == NULL ||
	    nla_parse_nested(attrs, DISPATCHER_DEST_ATTR_MAX, nla, dispatcher_dest_policy))
		return -EINVAL;

	nla_addr	= attrs[DISPATCHER_DEST_ATTR_ADDR];
	nla_port	= attrs[DISPATCHER_DEST_ATTR_PORT];

	if (!(nla_addr && nla_port))
		return -EINVAL;

	memset(udest, 0, sizeof(*udest));

	nla_memcpy(&udest->addr, nla_addr, sizeof(udest->addr));
	udest->port = nla_get_u16(nla_port);

	return 0;
}

static int dispatcher_genl_set_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct dispatcher_service *svc = NULL;
	struct dispatcher_service_user_kern usvc;
	struct dispatcher_dest_user_kern udest;
	int ret = 0, cmd;
	int need_full_svc = 0, need_full_dest = 0;

	cmd = info->genlhdr->cmd;

	mutex_lock(&__dispatcher_mutex);

	if (cmd == DISPATCHER_CMD_FLUSH) {
		ret = dispatcher_flush();
		goto out;
	}

	/* All following commands require a service argument, so check if we
	 * received a valid one. We need a full service specification when
	 * adding / editing a service. Only identifying members otherwise. */
	if (cmd == DISPATCHER_CMD_NEW_SERVICE || cmd == DISPATCHER_CMD_SET_SERVICE)
		need_full_svc = 1;

	ret = dispatcher_genl_parse_service(&usvc,
				       info->attrs[DISPATCHER_CMD_ATTR_SERVICE],
				       need_full_svc);
	if (ret)
		goto out;

	/* Lookup the exact service by <protocol, addr, port>*/
	svc = __dispatcher_service_get(usvc.af, usvc.protocol,
					  &usvc.addr, usvc.port);

	/* Unless we're adding a new service, the service must already exist */
	if ((cmd != DISPATCHER_CMD_NEW_SERVICE) && (svc == NULL)) {
		ret = -ESRCH;
		goto out;
	}

	/* Destination commands require a valid destination argument. For
	 * adding / editing a destination, we need a full destination
	 * specification. */
	if (cmd == DISPATCHER_CMD_NEW_DEST || cmd == DISPATCHER_CMD_SET_DEST ||
	    cmd == DISPATCHER_CMD_DEL_DEST) {
		if (cmd != DISPATCHER_CMD_DEL_DEST)
			need_full_dest = 1;

		ret = dispatcher_genl_parse_dest(&udest,
					    info->attrs[DISPATCHER_CMD_ATTR_DEST],
					    need_full_dest);
		if (ret)
			goto out;
	}

	switch (cmd) {
	case DISPATCHER_CMD_NEW_SERVICE:
		if (svc == NULL)
			ret = dispatcher_add_service(&usvc, &svc);
		else
			ret = -EEXIST;
		break;
	case DISPATCHER_CMD_DEL_SERVICE:
		ret = dispatcher_del_service(svc);
		break;
	case DISPATCHER_CMD_NEW_DEST:
		ret = dispatcher_add_dest(svc, &udest);
		break;
	case DISPATCHER_CMD_DEL_DEST:
		ret = dispatcher_del_dest(svc, &udest);
		break;
	default:
		ret = -EINVAL;
	}

out:
	if (svc)
		dispatcher_service_put(svc);
	mutex_unlock(&__dispatcher_mutex);

	return ret;
}

static int dispatcher_genl_get_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *reply;
	int ret, cmd, reply_cmd;

	cmd = info->genlhdr->cmd;

	if (cmd == DISPATCHER_CMD_GET_SERVICE)
		reply_cmd = DISPATCHER_CMD_NEW_SERVICE;
	else if (cmd == DISPATCHER_CMD_GET_INFO)
		reply_cmd = DISPATCHER_CMD_SET_INFO;
	else {
		pr_err("unknown Generic Netlink command\n");
		return -EINVAL;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	mutex_lock(&__dispatcher_mutex);

	reply = genlmsg_put_reply(msg, info, &dispatcher_genl_family, 0, reply_cmd);
	if (reply == NULL)
		goto nla_put_failure;

	switch (cmd) {
	case DISPATCHER_CMD_GET_SERVICE:
	{
		struct dispatcher_service *svc;

		svc = dispatcher_genl_find_service(info->attrs[DISPATCHER_CMD_ATTR_SERVICE]);
		if (IS_ERR(svc)) {
			ret = PTR_ERR(svc);
			goto out_err;
		} else if (svc) {
			ret = dispatcher_genl_fill_service(msg, svc);
			dispatcher_service_put(svc);
			if (ret)
				goto nla_put_failure;
		} else {
			ret = -ESRCH;
			goto out_err;
		}

		break;
	}

	case DISPATCHER_CMD_GET_INFO:
		NLA_PUT_U32(msg, DISPATCHER_INFO_ATTR_VERSION, DISPATCHER_VERSION_CODE);
		break;
	}

	genlmsg_end(msg, reply);
	ret = genlmsg_reply(msg, info);
	goto out;

nla_put_failure:
	pr_err("not enough space in Netlink message\n");
	ret = -EMSGSIZE;

out_err:
	nlmsg_free(msg);
out:
	mutex_unlock(&__dispatcher_mutex);

	return ret;
}


static struct genl_ops dispatcher_genl_ops[] __read_mostly = {
	{
		.cmd	= DISPATCHER_CMD_NEW_SERVICE,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_SET_SERVICE,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_DEL_SERVICE,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_GET_SERVICE,
		.flags	= GENL_ADMIN_PERM,
		.doit	= dispatcher_genl_get_cmd,
		.dumpit	= dispatcher_genl_dump_services,
		.policy	= dispatcher_cmd_policy,
	},
	{
		.cmd	= DISPATCHER_CMD_NEW_DEST,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_SET_DEST,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_DEL_DEST,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.doit	= dispatcher_genl_set_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_GET_DEST,
		.flags	= GENL_ADMIN_PERM,
		.policy	= dispatcher_cmd_policy,
		.dumpit	= dispatcher_genl_dump_dests,
	},
	{
		.cmd	= DISPATCHER_CMD_GET_INFO,
		.flags	= GENL_ADMIN_PERM,
		.doit	= dispatcher_genl_get_cmd,
	},
	{
		.cmd	= DISPATCHER_CMD_FLUSH,
		.flags	= GENL_ADMIN_PERM,
		.doit	= dispatcher_genl_set_cmd,
	},
};

static int __init dispatcher_genl_register(void)
{
	return genl_register_family_with_ops(&dispatcher_genl_family,
		dispatcher_genl_ops, ARRAY_SIZE(dispatcher_genl_ops));
}

static void dispatcher_genl_unregister(void)
{
	genl_unregister_family(&dispatcher_genl_family);
}

/* End of Generic Netlink interface definitions */


int __init dispatcher_control_init(void)
{
	int ret;
	int idx;

	EnterFunction(2);

	ret = nf_register_sockopt(&dispatcher_sockopts);
	if (ret) {
		pr_err("cannot register sockopt.\n");
		return ret;
	}

	ret = dispatcher_genl_register();
	if (ret) {
		pr_err("cannot register Generic Netlink interface.\n");
		nf_unregister_sockopt(&dispatcher_sockopts);
		return ret;
	}

	proc_net_fops_create(&init_net, "dispatcher", 0, &dispatcher_info_fops);

	sysctl_header = register_sysctl_paths(net_vs_ctl_path, vs_vars);

	/* Initialize dispatcher_svc_table, dispatcher_svc_fwm_table, dispatcher_rtable */
	for(idx = 0; idx < DISPATCHER_SVC_TAB_SIZE; idx++)  {
		INIT_LIST_HEAD(&dispatcher_svc_table[idx]);
	}
	for(idx = 0; idx < DISPATCHER_RTAB_SIZE; idx++)  {
		INIT_LIST_HEAD(&dispatcher_rtable[idx]);
	}

	LeaveFunction(2);
	return 0;
}


void dispatcher_control_cleanup(void)
{
	EnterFunction(2);
	dispatcher_trash_cleanup();
	unregister_sysctl_table(sysctl_header);
	proc_net_remove(&init_net, "dispatcher");
	dispatcher_genl_unregister();
	nf_unregister_sockopt(&dispatcher_sockopts);
	LeaveFunction(2);
}
