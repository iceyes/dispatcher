/*
 *      IP Virtual Server
 *      data structure and functionality definitions
 */

#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <linux/types.h>	/* For __beXX types in userland */

#define DISPATCHER_VERSION_CODE	0x010201
#define NVERSION(version)			\
	(version >> 16) & 0xFF,			\
	(version >> 8) & 0xFF,			\
	version & 0xFF


/*
 *      DISPATCHER socket options
 */
#define DISPATCHER_BASE_CTL		(64+1024+64)		/* base */

#define DISPATCHER_SO_SET_NONE	DISPATCHER_BASE_CTL		/* just peek */
#define DISPATCHER_SO_SET_INSERT	(DISPATCHER_BASE_CTL+1)
#define DISPATCHER_SO_SET_ADD	(DISPATCHER_BASE_CTL+2)
#define DISPATCHER_SO_SET_DEL	(DISPATCHER_BASE_CTL+3)
#define DISPATCHER_SO_SET_FLUSH	(DISPATCHER_BASE_CTL+4)
#define DISPATCHER_SO_SET_LIST	(DISPATCHER_BASE_CTL+5)
#define DISPATCHER_SO_SET_ADDDEST	(DISPATCHER_BASE_CTL+6)
#define DISPATCHER_SO_SET_DELDEST	(DISPATCHER_BASE_CTL+7)
#define DISPATCHER_SO_SET_RESTORE    (DISPATCHER_BASE_CTL+8)
#define DISPATCHER_SO_SET_SAVE       (DISPATCHER_BASE_CTL+9)
#define DISPATCHER_SO_SET_MAX	DISPATCHER_SO_SET_SAVE

#define DISPATCHER_SO_GET_VERSION	DISPATCHER_BASE_CTL
#define DISPATCHER_SO_GET_INFO	(DISPATCHER_BASE_CTL+1)
#define DISPATCHER_SO_GET_SERVICES	(DISPATCHER_BASE_CTL+2)
#define DISPATCHER_SO_GET_SERVICE	(DISPATCHER_BASE_CTL+3)
#define DISPATCHER_SO_GET_DESTS	(DISPATCHER_BASE_CTL+4)
#define DISPATCHER_SO_GET_DEST	(DISPATCHER_BASE_CTL+5)	/* not used now */
#define DISPATCHER_SO_GET_MAX	DISPATCHER_SO_GET_DEST

#define DISPATCHER_IFNAME_MAXLEN	16


/*
 *	The struct dispatcher_service_user and struct dispatcher_dest_user are
 *	used to set DISPATCHER rules through setsockopt.
 */
struct dispatcher_service_user {
	/* virtual service addresses */
	__u16		protocol;
	__be32			addr;		/* virtual ip address */
	__be16			port;

	__be32			netmask;	/* persistent netmask */
};


struct dispatcher_dest_user {
	/* destination server address */
	__be32			addr;
	__be16			port;
};

/* The argument to DISPATCHER_SO_GET_INFO */
struct dispatcher_getinfo {
	/* version number */
	unsigned int		version;

	/* number of virtual services */
	unsigned int		num_services;
};


/* The argument to DISPATCHER_SO_GET_SERVICE */
struct dispatcher_service_entry {
	/* which service: user fills in these */
	__u16		protocol;
	__be32			addr;		/* virtual address */
	__be16			port;

	__be32			netmask;	/* persistent netmask */

	/* number of real servers */
	unsigned int		num_dests;

};


struct dispatcher_dest_entry {
	__be32			addr;		/* destination address */
	__be16			port;
};


/* The argument to DISPATCHER_SO_GET_DESTS */
struct dispatcher_get_dests {
	/* which service: user fills in these */
	__u16		protocol;
	__be32			addr;		/* virtual address */
	__be16			port;

	/* number of real servers */
	unsigned int		num_dests;

	/* the real servers */
	struct dispatcher_dest_entry	entrytable[0];
};


/* The argument to DISPATCHER_SO_GET_SERVICES */
struct dispatcher_get_services {
	/* number of virtual services */
	unsigned int		num_services;

	/* service table */
	struct dispatcher_service_entry entrytable[0];
};


#define DISPATCHER_GENL_NAME		"DISPATCHER"
#define DISPATCHER_GENL_VERSION	0x1

/* Generic Netlink command attributes */
enum {
	DISPATCHER_CMD_UNSPEC = 0,

	DISPATCHER_CMD_NEW_SERVICE,		/* add service */
	DISPATCHER_CMD_SET_SERVICE,		/* modify service */
	DISPATCHER_CMD_DEL_SERVICE,		/* delete service */
	DISPATCHER_CMD_GET_SERVICE,		/* get service info */

	DISPATCHER_CMD_NEW_DEST,		/* add destination */
	DISPATCHER_CMD_SET_DEST,		/* modify destination */
	DISPATCHER_CMD_DEL_DEST,		/* delete destination */
	DISPATCHER_CMD_GET_DEST,		/* get destination info */

	DISPATCHER_CMD_SET_INFO,		/* only used in GET_INFO reply */
	DISPATCHER_CMD_GET_INFO,		/* get general DISPATCHER info */

	DISPATCHER_CMD_FLUSH,			/* flush services and dests */

	__DISPATCHER_CMD_MAX,
};

#define DISPATCHER_CMD_MAX (__DISPATCHER_CMD_MAX - 1)

/* Attributes used in the first level of commands */
enum {
	DISPATCHER_CMD_ATTR_UNSPEC = 0,
	DISPATCHER_CMD_ATTR_SERVICE,		/* nested service attribute */
	DISPATCHER_CMD_ATTR_DEST,		/* nested destination attribute */
	__DISPATCHER_CMD_ATTR_MAX,
};

#define DISPATCHER_CMD_ATTR_MAX (__DISPATCHER_SVC_ATTR_MAX - 1)

/*
 * Attributes used to describe a service
 *
 * Used inside nested attribute DISPATCHER_CMD_ATTR_SERVICE
 */
enum {
	DISPATCHER_SVC_ATTR_UNSPEC = 0,
	DISPATCHER_SVC_ATTR_AF,		/* address family */
	DISPATCHER_SVC_ATTR_PROTOCOL,		/* virtual service protocol */
	DISPATCHER_SVC_ATTR_ADDR,		/* virtual service address */
	DISPATCHER_SVC_ATTR_PORT,		/* virtual service port */

	DISPATCHER_SVC_ATTR_NETMASK,		/* persistent netmask */
	__DISPATCHER_SVC_ATTR_MAX,
};

#define DISPATCHER_SVC_ATTR_MAX (__DISPATCHER_SVC_ATTR_MAX - 1)

/*
 * Attributes used to describe a destination (real server)
 *
 * Used inside nested attribute DISPATCHER_CMD_ATTR_DEST
 */
enum {
	DISPATCHER_DEST_ATTR_UNSPEC = 0,
	DISPATCHER_DEST_ATTR_ADDR,		/* real server address */
	DISPATCHER_DEST_ATTR_PORT,		/* real server port */

	__DISPATCHER_DEST_ATTR_MAX,
};

#define DISPATCHER_DEST_ATTR_MAX (__DISPATCHER_DEST_ATTR_MAX - 1)


/* Attributes used in response to DISPATCHER_CMD_GET_INFO command */
enum {
	DISPATCHER_INFO_ATTR_UNSPEC = 0,
	DISPATCHER_INFO_ATTR_VERSION,		/* DISPATCHER version number */
	__DISPATCHER_INFO_ATTR_MAX,
};

#define DISPATCHER_INFO_ATTR_MAX (__DISPATCHER_INFO_ATTR_MAX - 1)

#endif	/* _DISPATCHER_H */
