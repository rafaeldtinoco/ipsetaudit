#include <uapi/linux/ptrace.h>
#include <net/sock.h>

#define TASK_COMM_LEN 16
#define IPSET_MAXNAMELEN 32

extern int daemonize;

// GENERAL

enum ev_type {
	EXCHANGE_CREATE = 1,
	EXCHANGE_DESTROY = 2,
	EXCHANGE_FLUSH = 3,
	EXCHANGE_RENAME = 4,
	EXCHANGE_SWAP = 5,
	EXCHANGE_DUMP = 6,
	EXCHANGE_TEST = 7,
	EXCHANGE_ADD = 8,
	EXCHANGE_DEL = 9,
};

struct data_t {
	u32 pid;
	u32 uid;
	u32 gid;
	u32 loginuid;
	u32 ret;
	enum ev_type etype;
	char comm[TASK_COMM_LEN];
	char ipset_name[IPSET_MAXNAMELEN];
	char ipset_newname[IPSET_MAXNAMELEN];
	char ipset_type[IPSET_MAXNAMELEN];
};

// IPSET RELATED

typedef __u16 ip_set_id_t;

struct ip_set_net {
	struct ip_set  *ip_set_list;
	ip_set_id_t	ip_set_max;
	bool		is_deleted;
	bool		is_destroyed;
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

// NETLINK RELATED

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

// MAIN

BPF_PERF_OUTPUT(events);

static __always_inline
int probe_enter(enum ev_type etype, void *ctx, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	struct data_t data = {};
	struct task_struct *task = (void *) bpf_get_current_task();

	data.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	data.pid = tgid;
	data.uid = uid;
	data.gid = gid;
	data.loginuid = task->loginuid.val;
	data.etype = etype;

	// netlink parsing

	struct nlattr *nla_name, *nla_name2, *nla_type;
	bpf_probe_read(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	bpf_probe_read_str(&data.ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (data.etype) {
	case EXCHANGE_CREATE:
		bpf_probe_read(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		bpf_probe_read_str(&data.ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
		break;
		;;
	case EXCHANGE_DESTROY:
		break;
		;;
	case EXCHANGE_FLUSH:
		break;
		;;
	case EXCHANGE_RENAME:
		bpf_probe_read(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		bpf_probe_read_str(&data.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_SWAP:
		bpf_probe_read(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		bpf_probe_read_str(&data.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_DUMP:
		break;
		;;
	case EXCHANGE_TEST:
		break;
		;;
	case EXCHANGE_ADD:
		break;
		;;
	case EXCHANGE_DEL:
		break;
		;;
	}

	return events.perf_submit(ctx, &data, sizeof(data));
}

int kprobe__ip_set_create(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_CREATE, ctx, nlh, attr);
}

int kprobe__ip_set_destroy(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_DESTROY, ctx, nlh, attr);
}
int kprobe__ip_set_flush(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_FLUSH, ctx, nlh, attr);
}
int kprobe__ip_set_rename(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_RENAME, ctx, nlh, attr);
}
int kprobe__ip_set_swap(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_SWAP, ctx, nlh, attr);
}
int kprobe__ip_set_dump(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_DUMP, ctx, nlh, attr);
}
int kprobe__ip_set_utest(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_TEST, ctx, nlh, attr);
}
int kprobe__ip_set_uadd(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_ADD, ctx, nlh, attr);
}
int kprobe__ip_set_udel(struct pt_regs *ctx, struct net *net, struct sock *ctnl,
		struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
{
	return probe_enter(EXCHANGE_DEL, ctx, nlh, attr);
}

