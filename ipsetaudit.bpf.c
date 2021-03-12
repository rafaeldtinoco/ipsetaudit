#ifdef NOTBCC
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#endif

#include "ipsetaudit.h"

#ifdef NOTBCC
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
#endif

// BCC / LIBBPF COMPAT

static __always_inline long
wrap_probe_read(void *dst, size_t sz, void *src)
{
#ifdef NOTBCC
	return bpf_probe_read_kernel(dst, sz, src);
#else
	return bpf_probe_read(dst, sz, src);
#endif
}

static __always_inline long
wrap_probe_read_str(void *dst, size_t sz, void *src)
{
#ifdef NOTBCC
	return bpf_probe_read_kernel_str(dst, sz, src);
#else
	return bpf_probe_read_str(dst, sz, src);
#endif
}

// IP_SET RELATED

static __always_inline int
probe_enter(enum ev_type etype, void *ctx, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	struct data_t data = {};
	struct task_struct *task = (void *) bpf_get_current_task();

	data.pid = tgid;
	data.uid = uid;
	data.uid = gid;
	data.etype = etype;

	wrap_probe_read_str(&data.comm, TASK_COMM_LEN, task->comm);

#ifdef NOTBCC // not sure why this does not work in BCC
	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);
#else
	data.loginuid = task->loginuid.val;
#endif

	// netlink parsing

	struct nlattr *nla_name, *nla_name2, *nla_type;
	wrap_probe_read(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	wrap_probe_read_str(&data.ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (data.etype) {
	case EXCHANGE_CREATE:
		wrap_probe_read(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		wrap_probe_read_str(&data.ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
		break;
		;;
	case EXCHANGE_DESTROY:
		break;
		;;
	case EXCHANGE_FLUSH:
		break;
		;;
	case EXCHANGE_RENAME:
		wrap_probe_read(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		wrap_probe_read_str(&data.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
		break;
		;;
	case EXCHANGE_SWAP:
		wrap_probe_read(&nla_name2, sizeof(void *), &attr[IPSET_ATTR_SETNAME2]);
		wrap_probe_read_str(&data.ipset_newname, IPSET_MAXNAMELEN, nla_data(nla_name2));
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

#ifdef NOTBCC
	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
#else
	return events.perf_submit(ctx, &data, sizeof(data));
#endif
}

#ifdef NOTBCC

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

#else // this is better organized than ifdefs per probe

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

#endif // BCC

char LICENSE[] SEC("license") = "GPL";
