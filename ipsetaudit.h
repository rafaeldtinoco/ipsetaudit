#ifndef IPSETAUDIT_H_
#define IPSETAUDIT_H_

// GENERAL

#define TASK_COMM_LEN 16

#define HERE fprintf(stderr, "line %d, file %s, function %s\n", __LINE__, __FILE__, __func__)

#define EXITERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	exit(1);			\
}

#define RETERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	return -1;			\
}

#define CLEANERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	goto cleanup;			\
}

// IPSET RELATED

typedef __u16 ip_set_id_t;

struct ip_set_net {
	struct ip_set  *ip_set_list;
	ip_set_id_t	ip_set_max;
	bool		is_deleted;
	bool		is_destroyed;
};

#define IPSET_MAXNAMELEN 32

enum xchg_type {
	EXCHANGE_CREATE = 1,
	EXCHANGE_DESTROY = 2,
	EXCHANGE_FLUSH = 3,
	EXCHANGE_RENAME = 4,
	EXCHANGE_SWAP = 5,
	EXCHANGE_DUMP = 6,
};

struct exchange {
	enum xchg_type xtype;
	uint32_t uid;
	uint32_t gid;
	char comm[TASK_COMM_LEN];
	char ipset_name[IPSET_MAXNAMELEN];
	char ipset_newname[IPSET_MAXNAMELEN];
	char ipset_type[IPSET_MAXNAMELEN];
	int ret;
};

enum {
	IPSET_ATTR_UNSPEC,
	IPSET_ATTR_PROTOCOL,
	IPSET_ATTR_SETNAME,
	IPSET_ATTR_TYPENAME,
	IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME,
	IPSET_ATTR_REVISION,
	IPSET_ATTR_FAMILY,
	IPSET_ATTR_FLAGS,
	IPSET_ATTR_DATA,
	IPSET_ATTR_ADT,
	IPSET_ATTR_LINENO,
	IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_REVISION_MIN	= IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_INDEX,
	__IPSET_ATTR_CMD_MAX,
};
#define IPSET_ATTR_CMD_MAX (__IPSET_ATTR_CMD_MAX - 1)

enum {
	IPSET_ATTR_IP = IPSET_ATTR_UNSPEC + 1,
	IPSET_ATTR_IP_FROM = IPSET_ATTR_IP,
	IPSET_ATTR_IP_TO,
	IPSET_ATTR_CIDR,
	IPSET_ATTR_PORT,
	IPSET_ATTR_PORT_FROM = IPSET_ATTR_PORT,
	IPSET_ATTR_PORT_TO,
	IPSET_ATTR_TIMEOUT,
	IPSET_ATTR_PROTO,
	IPSET_ATTR_CADT_FLAGS,
	IPSET_ATTR_CADT_LINENO = IPSET_ATTR_LINENO,
	IPSET_ATTR_MARK,
	IPSET_ATTR_MARKMASK,
	IPSET_ATTR_CADT_MAX = 16,
	IPSET_ATTR_INITVAL,
	IPSET_ATTR_HASHSIZE,
	IPSET_ATTR_MAXELEM,
	IPSET_ATTR_NETMASK,
	IPSET_ATTR_BUCKETSIZE,
	IPSET_ATTR_RESIZE,
	IPSET_ATTR_SIZE,
	IPSET_ATTR_ELEMENTS,
	IPSET_ATTR_REFERENCES,
	IPSET_ATTR_MEMSIZE,
	__IPSET_ATTR_CREATE_MAX,
};
#define IPSET_ATTR_CREATE_MAX	(__IPSET_ATTR_CREATE_MAX - 1)

// NETLINK RELATED

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

#endif
