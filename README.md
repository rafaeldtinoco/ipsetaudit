# Auditing ipset calls portable eBPF daemon

Unfortunately audit is not capable of monitoring/logging calls to ipset
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
libbpf: sec 'kprobe/ip_set_create': found program 'ip_set_create' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(3) kprobe/ip_set_destroy, size 744, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_destroy': found program 'ip_set_destroy' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(4) kprobe/ip_set_flush, size 744, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_flush': found program 'ip_set_flush' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(5) kprobe/ip_set_rename, size 744, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_rename': found program 'ip_set_rename' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(6) kprobe/ip_set_swap, size 744, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_swap': found program 'ip_set_swap' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(7) kprobe/ip_set_dump, size 744, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_dump': found program 'ip_set_dump' at insn offset 0 (0 bytes), code size 93 insns (744 bytes)
libbpf: elf: section(8) kprobe/__find_set_type_get, size 136, link 0, flags 6, type=1
libbpf: sec 'kprobe/__find_set_type_get': found program '__find_set_type_get' at insn offset 0 (0 bytes), code size 17 insns (136 bytes)
libbpf: elf: section(9) kprobe/find_set_and_id, size 136, link 0, flags 6, type=1
libbpf: sec 'kprobe/find_set_and_id': found program 'find_set_and_id' at insn offset 0 (0 bytes), code size 17 insns (136 bytes)
libbpf: elf: section(10) kretprobe/ip_set_create, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_create': found program 'ip_set_create_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(11) kretprobe/ip_set_destroy, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_destroy': found program 'ip_set_destroy_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(12) kretprobe/ip_set_flush, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_flush': found program 'ip_set_flush_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(13) kretprobe/ip_set_rename, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_rename': found program 'ip_set_rename_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(14) kretprobe/ip_set_swap, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_swap': found program 'ip_set_swap_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(15) kretprobe/ip_set_dump, size 200, link 0, flags 6, type=1
libbpf: sec 'kretprobe/ip_set_dump': found program 'ip_set_dump_ret' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(16) license, size 4, link 0, flags 3, type=1
libbpf: license of ipsetaudit_bpf is GPL
libbpf: elf: section(17) .maps, size 48, link 0, flags 3, type=1
libbpf: elf: section(18) .bss, size 128, link 0, flags 3, type=8
libbpf: elf: section(19) .BTF, size 28909, link 0, flags 0, type=1
libbpf: elf: section(20) .BTF.ext, size 5452, link 0, flags 0, type=1
libbpf: elf: section(21) .symtab, size 1296, link 39, flags 0, type=2
libbpf: elf: section(22) .relkprobe/ip_set_create, size 64, link 21, flags 0, type=9
libbpf: elf: section(23) .relkprobe/ip_set_destroy, size 64, link 21, flags 0, type=9
libbpf: elf: section(24) .relkprobe/ip_set_flush, size 64, link 21, flags 0, type=9
libbpf: elf: section(25) .relkprobe/ip_set_rename, size 64, link 21, flags 0, type=9
libbpf: elf: section(26) .relkprobe/ip_set_swap, size 64, link 21, flags 0, type=9
libbpf: elf: section(27) .relkprobe/ip_set_dump, size 64, link 21, flags 0, type=9
libbpf: elf: section(28) .relkprobe/__find_set_type_get, size 16, link 21, flags 0, type=9
libbpf: elf: section(29) .relkprobe/find_set_and_id, size 16, link 21, flags 0, type=9
libbpf: elf: section(30) .relkretprobe/ip_set_create, size 48, link 21, flags 0, type=9
libbpf: elf: section(31) .relkretprobe/ip_set_destroy, size 48, link 21, flags 0, type=9
libbpf: elf: section(32) .relkretprobe/ip_set_flush, size 48, link 21, flags 0, type=9
libbpf: elf: section(33) .relkretprobe/ip_set_rename, size 48, link 21, flags 0, type=9
libbpf: elf: section(34) .relkretprobe/ip_set_swap, size 48, link 21, flags 0, type=9
libbpf: elf: section(35) .relkretprobe/ip_set_dump, size 48, link 21, flags 0, type=9
libbpf: looking for externs among 54 symbols...
libbpf: collected 0 externs total
libbpf: map 'ongoing': at sec_idx 17, offset 0.
libbpf: map 'ongoing': found type = 1.
libbpf: map 'ongoing': found key [6], sz = 4.
libbpf: map 'ongoing': found value [10], sz = 128.
libbpf: map 'exchange': at sec_idx 17, offset 24.
libbpf: map 'exchange': found type = 1.
libbpf: map 'exchange': found key [6], sz = 4.
libbpf: map 'exchange': found value [10], sz = 128.
libbpf: map 'ipsetaud.bss' (global data): at sec_idx 18, offset 0, flags 400.
libbpf: map 2 is "ipsetaud.bss"
libbpf: sec '.relkprobe/ip_set_create': collecting relocation for section(2) 'kprobe/ip_set_create'
libbpf: sec '.relkprobe/ip_set_create': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_create': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_create': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_create': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_create': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_create': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_create': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_create': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/ip_set_destroy': collecting relocation for section(3) 'kprobe/ip_set_destroy'
libbpf: sec '.relkprobe/ip_set_destroy': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_destroy': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_destroy': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_destroy': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_destroy': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_destroy': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_destroy': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_destroy': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/ip_set_flush': collecting relocation for section(4) 'kprobe/ip_set_flush'
libbpf: sec '.relkprobe/ip_set_flush': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_flush': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_flush': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_flush': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_flush': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_flush': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_flush': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_flush': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/ip_set_rename': collecting relocation for section(5) 'kprobe/ip_set_rename'
libbpf: sec '.relkprobe/ip_set_rename': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_rename': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_rename': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_rename': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_rename': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_rename': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_rename': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_rename': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/ip_set_swap': collecting relocation for section(6) 'kprobe/ip_set_swap'
libbpf: sec '.relkprobe/ip_set_swap': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_swap': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_swap': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_swap': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_swap': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_swap': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_swap': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_swap': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/ip_set_dump': collecting relocation for section(7) 'kprobe/ip_set_dump'
libbpf: sec '.relkprobe/ip_set_dump': relo #0: insn #12 against 'ongoing'
libbpf: prog 'ip_set_dump': found map 0 (ongoing, sec 17, off 0) for insn #12
libbpf: sec '.relkprobe/ip_set_dump': relo #1: insn #19 against 'ongoing'
libbpf: prog 'ip_set_dump': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkprobe/ip_set_dump': relo #2: insn #22 against '.bss'
libbpf: prog 'ip_set_dump': found data map 2 (ipsetaud.bss, sec 18, off 0) for insn 22
libbpf: sec '.relkprobe/ip_set_dump': relo #3: insn #26 against 'ongoing'
libbpf: prog 'ip_set_dump': found map 0 (ongoing, sec 17, off 0) for insn #26
libbpf: sec '.relkprobe/__find_set_type_get': collecting relocation for section(8) 'kprobe/__find_set_type_get'
libbpf: sec '.relkprobe/__find_set_type_get': relo #0: insn #6 against 'ongoing'
libbpf: prog '__find_set_type_get': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkprobe/find_set_and_id': collecting relocation for section(9) 'kprobe/find_set_and_id'
libbpf: sec '.relkprobe/find_set_and_id': relo #0: insn #6 against 'ongoing'
libbpf: prog 'find_set_and_id': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_create': collecting relocation for section(10) 'kretprobe/ip_set_create'
libbpf: sec '.relkretprobe/ip_set_create': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_create_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_create': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_create_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_create': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_create_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkretprobe/ip_set_destroy': collecting relocation for section(11) 'kretprobe/ip_set_destroy'
libbpf: sec '.relkretprobe/ip_set_destroy': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_destroy_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_destroy': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_destroy_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_destroy': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_destroy_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkretprobe/ip_set_flush': collecting relocation for section(12) 'kretprobe/ip_set_flush'
libbpf: sec '.relkretprobe/ip_set_flush': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_flush_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_flush': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_flush_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_flush': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_flush_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkretprobe/ip_set_rename': collecting relocation for section(13) 'kretprobe/ip_set_rename'
libbpf: sec '.relkretprobe/ip_set_rename': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_rename_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_rename': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_rename_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_rename': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_rename_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkretprobe/ip_set_swap': collecting relocation for section(14) 'kretprobe/ip_set_swap'
libbpf: sec '.relkretprobe/ip_set_swap': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_swap_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_swap': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_swap_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_swap': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_swap_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: sec '.relkretprobe/ip_set_dump': collecting relocation for section(15) 'kretprobe/ip_set_dump'
libbpf: sec '.relkretprobe/ip_set_dump': relo #0: insn #6 against 'ongoing'
libbpf: prog 'ip_set_dump_ret': found map 0 (ongoing, sec 17, off 0) for insn #6
libbpf: sec '.relkretprobe/ip_set_dump': relo #1: insn #13 against 'exchange'
libbpf: prog 'ip_set_dump_ret': found map 1 (exchange, sec 17, off 24) for insn #13
libbpf: sec '.relkretprobe/ip_set_dump': relo #2: insn #19 against 'ongoing'
libbpf: prog 'ip_set_dump_ret': found map 0 (ongoing, sec 17, off 0) for insn #19
libbpf: loading kernel BTF '/sys/kernel/btf/vmlinux': 0
libbpf: map 'ongoing': created successfully, fd=4
libbpf: map 'exchange': created successfully, fd=5
libbpf: map 'ipsetaud.bss': created successfully, fd=6
libbpf: sec 'kprobe/ip_set_create': found 2 CO-RE relocations
libbpf: prog 'ip_set_create': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: CO-RE relocating [0] struct pt_regs: found target candidate [159] struct pt_regs in [vmlinux]
libbpf: prog 'ip_set_create': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_create': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_create': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: CO-RE relocating [0] struct task_struct: found target candidate [116] struct task_struct in [vmlinux]
libbpf: prog 'ip_set_create': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_create': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/ip_set_destroy': found 2 CO-RE relocations
libbpf: prog 'ip_set_destroy': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_destroy': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_destroy': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_destroy': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_destroy': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_destroy': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/ip_set_flush': found 2 CO-RE relocations
libbpf: prog 'ip_set_flush': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_flush': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_flush': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_flush': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_flush': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_flush': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/ip_set_rename': found 2 CO-RE relocations
libbpf: prog 'ip_set_rename': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_rename': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_rename': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_rename': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_rename': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_rename': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/ip_set_swap': found 2 CO-RE relocations
libbpf: prog 'ip_set_swap': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_swap': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_swap': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_swap': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_swap': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_swap': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/ip_set_dump': found 2 CO-RE relocations
libbpf: prog 'ip_set_dump': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_dump': relo #0: matching candidate #0 [159] struct pt_regs.r8 (0:9 @ offset 72)
libbpf: prog 'ip_set_dump': relo #0: patched insn #0 (LDX/ST/STX) off 72 -> 72
libbpf: prog 'ip_set_dump': relo #1: kind <byte_off> (0), spec is [25] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_dump': relo #1: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ip_set_dump': relo #1: patched insn #35 (ALU/ALU64) imm 2712 -> 2712
libbpf: sec 'kprobe/__find_set_type_get': found 1 CO-RE relocations
libbpf: prog '__find_set_type_get': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog '__find_set_type_get': relo #0: matching candidate #0 [159] struct pt_regs.di (0:14 @ offset 112)
libbpf: prog '__find_set_type_get': relo #0: patched insn #0 (LDX/ST/STX) off 112 -> 112
libbpf: sec 'kprobe/find_set_and_id': found 1 CO-RE relocations
libbpf: prog 'find_set_and_id': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.si (0:13 @ offset 104)
libbpf: prog 'find_set_and_id': relo #0: matching candidate #0 [159] struct pt_regs.si (0:13 @ offset 104)
libbpf: prog 'find_set_and_id': relo #0: patched insn #0 (LDX/ST/STX) off 104 -> 104
libbpf: sec 'kretprobe/ip_set_create': found 1 CO-RE relocations
libbpf: prog 'ip_set_create_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_create_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_create_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
libbpf: sec 'kretprobe/ip_set_destroy': found 1 CO-RE relocations
libbpf: prog 'ip_set_destroy_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_destroy_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_destroy_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
libbpf: sec 'kretprobe/ip_set_flush': found 1 CO-RE relocations
libbpf: prog 'ip_set_flush_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_flush_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_flush_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
libbpf: sec 'kretprobe/ip_set_rename': found 1 CO-RE relocations
libbpf: prog 'ip_set_rename_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_rename_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_rename_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
libbpf: sec 'kretprobe/ip_set_swap': found 1 CO-RE relocations
libbpf: prog 'ip_set_swap_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_swap_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_swap_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
libbpf: sec 'kretprobe/ip_set_dump': found 1 CO-RE relocations
libbpf: prog 'ip_set_dump_ret': relo #0: kind <byte_off> (0), spec is [21] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_dump_ret': relo #0: matching candidate #0 [159] struct pt_regs.ax (0:10 @ offset 80)
libbpf: prog 'ip_set_dump_ret': relo #0: patched insn #0 (LDX/ST/STX) off 80 -> 80
Tracing ipset commands... Hit Ctrl-C to end.
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495078) - RENAME ipset testando123 to testando123 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495080) - SWAP ipset testando456 to testando789 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495086) - DESTROY ipset testando789 - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495074) - CREATE ipset testando123 (type: hash:ip) - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495076) - CREATE ipset testando789 (type: hash:ip) - SUCCESS
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495082) - DESTROY ipset testando123 - ERROR
(2021/02/28_13:24) user: root (0), command: ipset (pid: 3495084) - DESTROY ipset testando456 - SUCCESS
```
