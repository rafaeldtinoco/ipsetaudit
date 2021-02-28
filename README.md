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
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679904) - DESTROY ipset test456 - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679905) - DESTROY ipset test789 - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679899) - IPSET TEST
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679898) - IPSET DUMP (SAVE/LIST)
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679902) - IPSET DUMP (SAVE/LIST)
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679897) - CREATE ipset test789 (type: hash:ip) - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679900) - RENAME ipset test123 to test456 - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679896) - CREATE ipset test123 (type: hash:ip) - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679901) - SWAP ipset test456 to test789 - SUCCESS
(2021/02/28_16:30) user: root (0), command: ipset (pid: 3679903) - DESTROY ipset test123 - ERROR

```
