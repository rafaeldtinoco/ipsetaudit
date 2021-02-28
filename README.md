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
(2021/02/28_17:37) ipset (pid: 3745445) - DESTROY test123 - ERROR
(2021/02/28_17:37) ipset (pid: 3745446) - DESTROY test456 - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745438) - CREATE test123 (type: hash:ip) - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745440) - SAVE/LIST  - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745444) - SAVE/LIST test456 - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745447) - DESTROY test789 - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745442) - RENAME test123 -> test456 - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745441) - TEST test123
(2021/02/28_17:37) ipset (pid: 3745439) - CREATE test789 (type: hash:ip) - SUCCESS
(2021/02/28_17:37) ipset (pid: 3745443) - SWAP test456 <-> test789 - SUCCESS
```
