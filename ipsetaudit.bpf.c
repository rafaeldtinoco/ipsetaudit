#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ipsetaudit.h"

// BPF MAPS

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// NETLINK RELATED

static __always_inline void *nla_data(struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

// IP_SET RELATED

static __always_inline int
probe_enter(enum ev_type etype, void *ctx, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	struct task_struct *this = (void *) bpf_get_current_task();
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	// construct an event

	struct event event = {};
	event.pid = tgid;
	event.uid = uid;
	event.uid = gid;
	event.etype = etype;
	bpf_probe_read_kernel_str(&event.comm, TASK_COMM_LEN, this->comm);

	// netlink parsing

	struct nlattr *nla_name, *nla_name2, *nla_type;
	bpf_probe_read_kernel(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	bpf_probe_read_kernel_str(&event.ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (event.etype) {
	case EXCHANGE_CREATE:
		bpf_probe_read_kernel(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		bpf_probe_read_kernel_str(&event.ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
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
		bpf_probe_read_kernel_str(&event.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_SWAP:
		bpf_probe_read_kernel(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		bpf_probe_read_kernel_str(&event.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
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

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &event, sizeof(event));
}

SEC("kprobe/ip_set_create")
int BPF_KPROBE(ip_set_create, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_CREATE, ctx, nlh, attr);
}

SEC("kprobe/ip_set_destroy")
int BPF_KPROBE(ip_set_destroy, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_DESTROY, ctx, nlh, attr);
}

SEC("kprobe/ip_set_flush")
int BPF_KPROBE(ip_set_flush, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_FLUSH, ctx, nlh, attr);
}

SEC("kprobe/ip_set_rename")
int BPF_KPROBE(ip_set_rename, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_RENAME, ctx, nlh, attr);
}

SEC("kprobe/ip_set_swap")
int BPF_KPROBE(ip_set_swap, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_SWAP, ctx, nlh, attr);
}

SEC("kprobe/ip_set_dump")
int BPF_KPROBE(ip_set_dump, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_DUMP, ctx, nlh, attr);
}

SEC("kprobe/ip_set_utest")
int BPF_KPROBE(ip_set_utest, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_TEST, ctx, nlh, attr);
}

SEC("kprobe/ip_set_uadd")
int BPF_KPROBE(ip_set_uadd, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_ADD, ctx, nlh, attr);
}

SEC("kprobe/ip_set_udel")
int BPF_KPROBE(ip_set_udel, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_DEL, ctx, nlh, attr);
}

/*
 * Unfortunately I think I'll need some sort of global data to link kprobe <-> kretprobe in here
 *
static __always_inline int
probe_return(enum xchg_type xtype, void *ctx, int ret)
{
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	if (!(xchg = bpf_map_lookup_elem(&ongoing, &tgid)))
		return 0;

	switch (xchg->xtype) {
	case EXCHANGE_DUMP:
		xchg->ret = 0;
		break;
	default:
		xchg->ret = ret;
		break;
	}

	bpf_map_update_elem(&exchange, &tgid, xchg, 0);
	bpf_map_delete_elem(&ongoing, &tgid);

	return 0;
}

SEC("kretprobe/ip_set_create")
int BPF_KRETPROBE(ip_set_create_ret, int ret)
{
	return probe_return(EXCHANGE_CREATE, ctx, ret);
}

SEC("kretprobe/ip_set_destroy")
int BPF_KRETPROBE(ip_set_destroy_ret, int ret)
{
	return probe_return(EXCHANGE_DESTROY, ctx, ret);
}

SEC("kretprobe/ip_set_flush")
int BPF_KRETPROBE(ip_set_flush_ret, int ret)
{
	return probe_return(EXCHANGE_FLUSH, ctx, ret);
}

SEC("kretprobe/ip_set_rename")
int BPF_KRETPROBE(ip_set_rename_ret, int ret)
{
	return probe_return(EXCHANGE_RENAME, ctx, ret);
}

SEC("kretprobe/ip_set_swap")
int BPF_KRETPROBE(ip_set_swap_ret, int ret)
{
	return probe_return(EXCHANGE_SWAP, ctx, ret);
}

SEC("kretprobe/ip_set_dump")
int BPF_KRETPROBE(ip_set_dump_ret, int ret)
{
	return probe_return(EXCHANGE_DUMP, ctx, ret);
}

SEC("kretprobe/ip_set_utest")
int BPF_KRETPROBE(ip_set_utest_ret, int ret)
{
	return probe_return(EXCHANGE_TEST, ctx, ret);
}
*/


char LICENSE[] SEC("license") = "GPL";
