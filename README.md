# Auditing ipset calls: a portable eBPF based userland daemon

Unfortunately [audit](https://github.com/linux-audit/audit-documentation/wiki) is not capable of logging
[IPset](https://en.wikipedia.org/wiki/Netfilter#ipset) calls, as those are managed by a
[netlink](https://en.wikipedia.org/wiki/Netlink) socket. **IPsetAudit** allows you to log (and audit)
IPset creation/deletion/modifications by probing kernel internal netlink handlers and passing information
to its userland daemon.

> Note: This code is being activelly developed and will change until its final release.

## Output example

```
$ sudo ./ipsetaudit
libbpf: loading object 'ipsetaudit_bpf' from buffer
libbpf: elf: section(2) kprobe/ip_set_create, size 744, link 0, flags 6, type=1
...
Tracing ipset commands... Hit Ctrl-C to end.
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656347) - DESTROY ipset testando123 - ERROR
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656345) - SWAP ipset testando456 to testando789 - SUCCESS
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656403) - DESTROY ipset testando789 - SUCCESS
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656349) - DESTROY ipset testando456 - SUCCESS
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656338) - CREATE ipset testando123 (type: hash:ip) - SUCCESS
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656340) - CREATE ipset testando789 (type: hash:ip) - SUCCESS
(2021/02/28_16:10) user: root (0), command: ipset (pid: 3656343) - RENAME ipset testando123 to testando456 - SUCCESS
```
