# Auditing ipset calls portable eBPF daemon

Unfortunately auditd is not capable of monitoring/logging calls to ipset
subsystem as this is mainly managed by netlink sockets. For that reason,
this daemon is needed: It creates an userland daemon that receives information
from in-kernel netlink subsystem and logs it into syslog, this way you can
audit changes to ipsets while they happen.

> Note: This code is being activelly developed and will change until its final release.

## Output example

```
$ sudo ./ipsetaudit
libbpf: loading object 'ipsetaudit_bpf' from buffer
libbpf: elf: section(2) kprobe/ip_set_create, size 744, link 0, flags 6, type=1
...
Tracing ipset commands... Hit Ctrl-C to end.
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495078) - RENAME ipset testando123 to testando123 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495080) - SWAP ipset testando456 to testando789 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495086) - DESTROY ipset testando789 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495074) - CREATE ipset testando123 (type: hash:ip) - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495076) - CREATE ipset testando789 (type: hash:ip) - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495082) - DESTROY ipset testando123 - ERROR
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495084) - DESTROY ipset testando456 - SUCCESS
```
