#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ipsetaudit.h"

// BPF MAPS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct exchange);
} ongoing SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct exchange);
} exchange SEC(".maps");

static struct exchange initial_ongoing;
static struct exchange initial_xchg;

// NETLINK RELATED

static __always_inline void *nla_data(struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

// IP_SET RELATED

static __always_inline int
probe_enter(enum xchg_type xtype, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	struct exchange *xchg;
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;

	u64 ts = bpf_ktime_get_ns();
	struct task_struct *this = (void *) bpf_get_current_task();

	// initialization to find (or create) map for current task

	if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid))) {
		bpf_map_update_elem(&ongoing, &tgid, &initial_ongoing, 0);
		if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid)))
			return 1;
	}

	xchg->uid = uid;
	xchg->uid = gid;
	bpf_probe_read_kernel_str(&xchg->comm, TASK_COMM_LEN, this->comm);

	// type of ipset exchange

	xchg->xtype = xtype;

	// netlink packages parsing

	struct nlattr *nla_name, *nla_name2, *nla_type;

	bpf_probe_read_kernel(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	bpf_probe_read_kernel_str(&xchg->ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (xchg->xtype) {
	case EXCHANGE_CREATE:
		bpf_probe_read_kernel(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		bpf_probe_read_kernel_str(&xchg->ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
		break;
		;;
	case EXCHANGE_DESTROY:
		break;
		;;
	case EXCHANGE_FLUSH:
		break;
		;;
	case EXCHANGE_RENAME:
		bpf_probe_read_kernel(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		bpf_probe_read_kernel_str(&xchg->ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_SWAP:
		bpf_probe_read_kernel(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		bpf_probe_read_kernel_str(&xchg->ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_DUMP:
		break;
		;;
	}

	return 0;
}

SEC("kprobe/ip_set_create")
int BPF_KPROBE(ip_set_create, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_CREATE, nlh, attr);
}

SEC("kprobe/ip_set_destroy")
int BPF_KPROBE(ip_set_destroy, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_DESTROY, nlh, attr);
}

SEC("kprobe/ip_set_flush")
int BPF_KPROBE(ip_set_flush, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_FLUSH, nlh, attr);
}

SEC("kprobe/ip_set_rename")
int BPF_KPROBE(ip_set_rename, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_RENAME, nlh, attr);
}

SEC("kprobe/ip_set_swap")
int BPF_KPROBE(ip_set_swap, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_SWAP, nlh, attr);
}

SEC("kprobe/ip_set_dump")
int BPF_KPROBE(ip_set_dump, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_DUMP, nlh, attr);
}

/*
 * Use similar approach if pointer can't be calculated in previous probes
 * I was using those while I wasn't being able to align NL MSGs, I am now
 *
SEC("kprobe/__find_set_type_get")
int BPF_KPROBE(__find_set_type_get, char *name)
{
	// workaround to get IPSET_ATTR_TYPENAME from subsquent calls from ip_set_create()

	struct exchange *xchg;
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid)))
		return 0;

	switch (xchg->xtype) {
	case EXCHANGE_CREATE:
		bpf_probe_read_kernel_str(&xchg->ipset_type, IPSET_MAXNAMELEN, name);
		break;
		;;
	default:
		break;
	}

	return 0;
}

SEC("kprobe/find_set_and_id")
int BPF_KPROBE(find_set_and_id, struct ip_set_net *inst, char *name)
{
	// workaround to get IPSET_ATTR_SETNAME2 from subsquent calls from ip_set_swap()

	struct exchange *xchg;
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid)))
		return 0;

	switch (xchg->xtype) {
	case EXCHANGE_SWAP:
		bpf_probe_read_kernel_str(&xchg->ipset_newname, IPSET_MAXNAMELEN, name);
		break;
		;;
	default:
		break;
	}

	return 0;
}
*/

static __always_inline int
probe_return(enum xchg_type xtype, int ret)
{
	struct exchange *xchg;
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid)))
		return 0;

	xchg->ret = ret;
	bpf_map_update_elem(&exchange, &tgid, xchg, 0);
	bpf_map_delete_elem(&ongoing, &tgid);

	return 0;
}

SEC("kretprobe/ip_set_create")
int BPF_KRETPROBE(ip_set_create_ret, int ret)
{
	return probe_return(EXCHANGE_CREATE, ret);
}

SEC("kretprobe/ip_set_destroy")
int BPF_KRETPROBE(ip_set_destroy_ret, int ret)
{
	return probe_return(EXCHANGE_DESTROY, ret);
}

SEC("kretprobe/ip_set_flush")
int BPF_KRETPROBE(ip_set_flush_ret, int ret)
{
	return probe_return(EXCHANGE_FLUSH, ret);
}

SEC("kretprobe/ip_set_rename")
int BPF_KRETPROBE(ip_set_rename_ret, int ret)
{
	return probe_return(EXCHANGE_RENAME, ret);
}

SEC("kretprobe/ip_set_swap")
int BPF_KRETPROBE(ip_set_swap_ret, int ret)
{
	return probe_return(EXCHANGE_SWAP, ret);
}

SEC("kretprobe/ip_set_dump")
int BPF_KRETPROBE(ip_set_dump_ret, int ret)
{
	return probe_return(EXCHANGE_DUMP, ret);
}

char LICENSE[] SEC("license") = "GPL";
