#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ipsetaudit.h"
#include "ipsetaudit.skel.h"

static volatile bool exiting;

// GENERAL

char *get_currtime(void)
{
	char *datetime = malloc(100);
	time_t t = time(NULL);
	struct tm *tmp;

	memset(datetime, 0, 100);

	if ((tmp = localtime(&t)) == NULL)
		EXITERR("could not get localtime");

	if ((strftime(datetime, 100, "%Y/%m/%d_%H:%M", tmp)) == 0)
		EXITERR("could not parse localtime");

	return datetime;
}

static int get_pid_max(void)
{
	FILE *f;
	int pid_max = 0;

	if ((f = fopen("/proc/sys/kernel/pid_max", "r")) < 0)
		RETERR("failed to open proc_sys pid_max");

	if (fscanf(f, "%d\n", &pid_max) != 1)
		RETERR("failed to read proc_sys pid_max");

	fclose(f);

	return pid_max;
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static void sig_handler(int sig)
{
	exiting = true;
}

char *get_username(uint32_t uid)
{
	char *username = malloc(100);
	struct passwd *p = getpwuid(uid);

	memset(username, 0, 100);
	strcpy(username, p->pw_name);

	return username;
}

// OUTPUT

static int print_created(int fd)
{
	char *currtime, *username, *what;
	uint32_t lookup_key = -2, next_key;
	struct exchange xchg;
	int err;

	currtime = get_currtime();

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		if((err = bpf_map_lookup_elem(fd, &next_key, &xchg)) < 0)
			EXITERR("failed to lookup created: %d\n", err);

		if ((username = get_username(xchg.uid)) == NULL)
			username = "null";

		switch (xchg.xtype) {
		case EXCHANGE_CREATE:
			what = "CREATE";
			printf("(%s) user: %s (%d), command: %s (pid: %d) - %s ipset %s (type: %s) - %s\n",
				currtime, username, xchg.uid, xchg.comm, next_key, what,
				xchg.ipset_name, xchg.ipset_type, xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_DESTROY:
			what = "DESTROY";
			break;
			;;
		case EXCHANGE_FLUSH:
			what = "FLUSH";
			break;
			;;
		case EXCHANGE_SWAP:
			what = "SWAP";
			printf("(%s) user: %s (%d), command: %s (pid: %d) - %s ipset %s to %s - %s\n",
				currtime, username, xchg.uid, xchg.comm, next_key, what,
				xchg.ipset_name, xchg.ipset_newname, xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_DUMP:
			what = "DUMP";
			break;
			;;
		case EXCHANGE_RENAME:
			what = "RENAME";
			printf("(%s) user: %s (%d), command: %s (pid: %d) - %s ipset %s to %s - %s\n",
				currtime, username, xchg.uid, xchg.comm, next_key, what,
				xchg.ipset_name, xchg.ipset_newname, xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		}

		printf("(%s) user: %s (%d), command: %s (pid: %d) - %s ipset %s - %s\n",
				currtime, username, xchg.uid, xchg.comm, next_key, what,
				xchg.ipset_name, xchg.ret ? "ERROR" : "SUCCESS");
after:
		if (username != NULL)
			free(username);

		lookup_key = next_key;
	}

	free(currtime);

	lookup_key = -2;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		if((err = bpf_map_delete_elem(fd, &next_key)) < 0)
			EXITERR("failed to cleanup created: %d\n", err);

		lookup_key = next_key;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// EBPF USERLAND PORTION

int main(int argc, char **argv)
{
	struct ipsetaudit_bpf *obj;
	int err, pid_max, fd;

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d\n", err);

	if (!(obj = ipsetaudit_bpf__open()))
		EXITERR("failed to open BPF object\n");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max\n");

	bpf_map__resize(obj->maps.exchange, pid_max);
	bpf_map__resize(obj->maps.ongoing, pid_max);

	if ((err = ipsetaudit_bpf__load(obj)))
		CLEANERR("failed to load BPF object: %d\n", err);

	if ((err = ipsetaudit_bpf__attach(obj)))
		CLEANERR("failed to attach BPF programs\n");

	fd = bpf_map__fd(obj->maps.exchange);

	signal(SIGINT, sig_handler);

	printf("Tracing ipset commands... Hit Ctrl-C to end.\n");

	while (1) {
		if ((err = print_created(fd)))
			break;

		if (exiting)
			break;

		sleep(2);
	}

cleanup:
	ipsetaudit_bpf__destroy(obj);
	return err != 0;
}
