#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ipsetaudit.h"
#include "ipsetaudit.skel.h"

int daemonize = 0;
static int bpfverbose = 0;
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

// LOGGING RELATED

void initlog()
{
	openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);
}

void endlog()
{
	closelog();
}

// DAEMON RELATED

int makemeadaemon(void)
{
	int fd;

	fprintf(stdout, "Daemon mode. Check syslog for messages!\n");

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	if (setsid() == -1)
		return -1;

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (chdir("/") == -1)
		return -1;

	close(0); close(1); close(2);

	fd = open("/dev/null", O_RDWR);

	if (fd != 0)
		return -1;
	if (dup2(0, 1) != 1)
		return -1;
	if (dup2(0, 2) != 2)
		return -1;

	return 0;
}

int dontmakemeadaemon(void)
{
	fprintf(stdout, "Foreground mode...<Ctrl-C> or or SIG_TERM to end it.\n");

	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return 0;
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

		// no need to be here, only root can send netlink to ipset
		if ((username = get_username(xchg.uid)) == NULL)
			username = "null";

		switch (xchg.xtype) {
		case EXCHANGE_CREATE:
			OUTPUT("(%s) %s (pid: %d) - CREATE %s (type: %s) - %s\n",
				currtime, xchg.comm, next_key,
				xchg.ipset_name, xchg.ipset_type,
				xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_SWAP:
			OUTPUT("(%s) %s (pid: %d) - SWAP %s <-> %s - %s\n",
				currtime, xchg.comm, next_key,
				xchg.ipset_name, xchg.ipset_newname,
				xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_DUMP:
			OUTPUT("(%s) %s (pid: %d) - SAVE/LIST %s - %s\n",
				currtime, xchg.comm, next_key,
				xchg.ipset_name,
				xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_RENAME:
			OUTPUT("(%s) %s (pid: %d) - RENAME %s -> %s - %s\n",
				currtime, xchg.comm, next_key,
				xchg.ipset_name, xchg.ipset_newname,
				xchg.ret ? "ERROR" : "SUCCESS");
			goto after;
			;;
		case EXCHANGE_TEST:
			what = "TEST";
			OUTPUT("(%s) %s (pid: %d) - %s %s\n",
				currtime, xchg.comm, next_key,
				what, xchg.ipset_name);
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
		case EXCHANGE_ADD:
			what = "ADD";
			break;
			;;
		case EXCHANGE_DEL:
			what = "DEL";
			break;
			;;
		}

		OUTPUT("(%s) %s (pid: %d) - %s %s - %s\n",
			currtime, xchg.comm, next_key,
			what, xchg.ipset_name,
		        xchg.ret ? "ERROR" : "SUCCESS");
after:
		if (username != NULL)
			free(username);

		lookup_key = next_key;
	}

	free(currtime);

	lookup_key = -2;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		if((err = bpf_map_delete_elem(fd, &next_key)) < 0)
			EXITERR("failed to cleanup created: %d", err);

		lookup_key = next_key;
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}

// USAGE

int usage(int argc, char **argv)
{
	fprintf(stdout,
		"\n"
		"Syntax: %s [options]\n"
		"\n"
		"\t[options]:\n"
		"\n"
		"\t-v: bpf verbose mode\n"
		"\t-d: daemon mode (output to syslog)\n"
		"\n"
		"Check https://rafaeldtinoco.github.io/ipsetaudit/ for more info!\n"
		"\n",
		argv[0]);

	exit(0);
}

// EBPF USERLAND PORTION

int main(int argc, char **argv)
{
	int opt, err = 0, pid_max, fd;
	struct ipsetaudit_bpf *obj;

	while ((opt = getopt(argc, argv, "hvd")) != -1) {
		switch(opt) {
		case 'v':
			bpfverbose = 1;
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'h':
		default:
			usage(argc, argv);
		}
	}

	daemonize ? err = makemeadaemon() : dontmakemeadaemon();

	if (err == -1)
		EXITERR("failed to become a deamon");

	if (daemonize)
		initlog();

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d", err);

	if (!(obj = ipsetaudit_bpf__open()))
		EXITERR("failed to open BPF object");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max");

	bpf_map__resize(obj->maps.exchange, pid_max);
	bpf_map__resize(obj->maps.ongoing, pid_max);

	if ((err = ipsetaudit_bpf__load(obj)))
		CLEANERR("failed to load BPF object: %d", err);

	if ((err = ipsetaudit_bpf__attach(obj)))
		CLEANERR("failed to attach BPF programs");

	fd = bpf_map__fd(obj->maps.exchange);

	signal(SIGINT, sig_handler);

	while (1) {
		if ((err = print_created(fd)))
			break;

		if (exiting)
			break;

		sleep(2);
	}

cleanup:
	if (daemonize)
		endlog();

	ipsetaudit_bpf__destroy(obj);

	return err != 0;
}
