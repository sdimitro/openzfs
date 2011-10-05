/*
 * Copyright (c) 2011 by Delphix.
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/devpoll.h>

/*
 * devpoll_test.c --
 *
 *	This file implements some simple tests to verify the behavior of the
 *	DP_POLL ioctl on /dev/poll.
 *
 * Background:
 *
 *	Several customers recently ran into an issue where threads in grizzly
 *	(java http server implementation) would randomly wake up from a java
 *	call to select against a java.nio.channels.Selector with no events ready
 *	but well before the specified timeout expired. The
 *	java.nio.channels.Selector select logic is implemented via /dev/poll.
 *	The selector opens /dev/poll, writes the file descriptors it wants to
 *	select on to the file descritpor, and then issues a DP_POLL ioctl to
 *	wait for events to be ready.
 *
 *	The DP_POLL ioctl arguments include a relative timeout in milliseconds,
 *	according to man poll.7d the ioctl should block until events are ready,
 *	the timeout expires, or a signal was received. In this case we noticed
 *	that DP_POLL was returning before the timeout expired despite no events
 *	being ready and no signal being delivered.
 *
 *	Using dtrace we discovered that DP_POLL was returning in cases where the
 *	system time was changed and the thread calling DP_POLL was woken up as
 *	a result of the process forking. The DP_POLL logic was in a loop
 *	checking if events were ready and then calling cv_waituntil_sig to
 *	block. cv_waituntil_sig will return -1 if the system time has changed,
 *	causing the DP_POLL to complete prematurely.
 *
 * Fix:
 *
 *	The fix changes dpioctl to use cv_relwait_sig rather then
 *	cv_waituntil_sig. cv_relwait_sig expects a relative timeout rather then
 *	an absolute timeout, so we avoid the problem.
 *
 * Test:
 *
 *	The test verifies that changing the date does not wake up threads
 *	blocked processing a DP_POLL ioctl. The test spawns one thread that
 *	changes the date and forks (to force the threads to wakeup from
 *	cv_relwait_sig) every two seconds. The test spawns a second thread that
 *	issues a DP_IOCTL on an fd set that will never have events ready and
 *	verifies that it does not return until the specified timeout expires.
 */

/*
 * The maximum amount of skew in seconds allowed between the
 * expected an actual time that a test takes.
 */
#define	TIME_DRIFT	1

static pthread_mutex_t	exitLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	exitCond = PTHREAD_COND_INITIALIZER;
static int		terminated = 0;

/*
 * Set via -d to enable debug logging
 */
static int debug = 0;

static void
debug_log(const char *format, ...)
{
	va_list	args;

	if (!debug) {
		return;
	}

	(void) printf("DEBUG: ");

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
}

static void
test_start(const char *testName, const char *format, ...)
{
	va_list	args;

	(void) printf("TEST STARTING %s: ", testName);

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
}

static void
test_failed(const char *testName, const char *format, ...)
{
	va_list	args;

	(void) printf("TEST FAILED %s: ", testName);

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);

	(void) exit(-1);
}

static void
test_passed(const char *testName)
{
	(void) printf("TEST PASS: %s\n", testName);
}

static int
check_time(time_t elapsed, time_t expected)
{
	time_t	diff = expected - elapsed;

	/*
	 * We may take slightly more or less time then expected,
	 * we allow for a small fudge factor if things completed
	 * before we expect them to.
	 */
	return (elapsed >= expected || diff <= TIME_DRIFT);
}

static int
dppoll(int pollFD, pollfd_t *fds, nfds_t nfds, int timeout, time_t *elapsed)
{
	struct dvpoll	arg;
	int		ret;
	time_t		start = time(NULL);

	arg.dp_fds = fds;
	arg.dp_nfds = nfds;
	arg.dp_timeout = timeout;

	debug_log("DP_POLL start: (0x%p, %d, %d)\n", fds, nfds, timeout);

	ret = ioctl(pollFD, DP_POLL, &arg);

	*elapsed = time(NULL) - start;

	debug_log("DP_POLL end: (0x%p, %d, %d) returns %d (elapse=%d)\n",
	    fds, arg.dp_nfds, arg.dp_timeout, ret, (*elapsed));

	return (ret);
}

static void
clear_fd(const char *testName, int pollFD, int testFD)
{
	int		ret;
	pollfd_t	fd;

	fd.fd = testFD;
	fd.events = POLLREMOVE;
	fd.revents = 0;

	ret = write(pollFD, &fd, sizeof (pollfd_t));

	if (ret != sizeof (pollfd_t)) {
		if (ret < 0) {
			test_failed(testName, "Failed to clear fd %d: %s",
			    testFD, strerror(ret));
		}


		test_failed(testName, "Failed to clear fd %d: %d", testFD, ret);
	}
}

/*
 * TEST poll-no-fd: DP_POLL with no FDs set, verify we wait the appropriate
 * amount of time.
 */
static void
poll_no_fd_test(int pollFD, int testFD)
{
	const char	*testName = "poll-no-fd";
	time_t		elapsed;
	int		timeout = 10;
	int		ret;

	test_start(testName, "poll for %d sec with no fds\n", timeout);

	ret = dppoll(pollFD, NULL, 0, timeout * 1000, &elapsed);

	if (ret != 0) {
		test_failed(testName, "DP_POLL returns %d (expected 0)\n", ret);
	}

	if (!check_time(elapsed, timeout)) {
		test_failed(testName, "took %d (expected %d)\n",
		    elapsed, timeout);
	}

	test_passed(testName);
}

/*
 * TEST poll-with-fds: DP_POLL with a valid FD set, verify that we wait
 * the appropriate amount of time.
 */
static void
poll_with_fds_test(int pollFD, int testFD)
{
	const char	*testName = "poll-with-fds";
	time_t		elapsed;
	int		timeout = 10;
	int		ret;
	pollfd_t	fds[5];

	test_start(testName, "poll for %d sec with fds\n", timeout);

	/*
	 * Clear the FD in case it's already in the cached set
	 */
	clear_fd(testName, pollFD, testFD);

	/*
	 * Add the FD with POLLIN
	 */
	fds[0].fd = testFD;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	ret = write(pollFD, fds, sizeof (pollfd_t));

	if (ret != sizeof (pollfd_t)) {
		if (ret < 0) {
			test_failed(testName, "Failed to set fds: %s",
			    strerror(ret));
		}

		test_failed(testName, "Failed to set fds: %d", ret);
	}

	ret = dppoll(pollFD, fds, 5, timeout * 1000, &elapsed);

	if (ret != 0) {
		test_failed(testName, "DP_POLL returns %d (expected 0)\n", ret);
	}

	if (!check_time(elapsed, timeout)) {
		test_failed(testName, "took %d (expected %d)\n",
		    elapsed, timeout);
	}

	clear_fd(testName, pollFD, testFD);

	test_passed(testName);
}

static void *
poll_thread(void *data)
{
	int	err;
	int	pollFD;
	int	testFD;
	char	*file = tmpnam(NULL);
	int	ret;

	pollFD = open("/dev/poll", O_RDWR);

	if (pollFD <  0) {
		perror("Failed to open /dev/poll: ");
		exit(-1);
	}

	/*
	 * Create a dummy FD that will never have POLLIN set
	 */
	testFD = socket(PF_INET, SOCK_STREAM, 0);

	poll_no_fd_test(pollFD, testFD);
	poll_with_fds_test(pollFD, testFD);

	close(testFD);
	close(pollFD);

	pthread_exit(0);
}

/*
 * This function causes any threads blocked in cv_timedwait_sig_hires
 * to wakeup, which allows us to test how dpioctl handles spurious
 * wakeups.
 */
trigger_wakeup(void)
{
	pid_t   child;

	/*
	 * Forking will force all of the threads to be woken up so
	 * they can be moved to a well known state.
	 */
	child = vfork();

	if (child == -1) {
		perror("Fork failed: ");
		exit(-1);
	} else if (child == 0) {
		exit(0);
	} else {
		pid_t   result = -1;
		int	status;

		do {
			result = waitpid(child, &status, 0);

			if (result == -1 && errno != EINTR) {
				(void) printf("Waitpid for %d failed: %s\n",
				    child, strerror(errno));
				exit(-1);
			}
		} while (result != child);

		if (status != 0) {
			(void) printf("Child pid %d failed: %d\n",
			    child, status);
			exit(-1);
		}
	}
}

/*
 * This function changes the system time, which has the side
 * effect of updating timechanged in the kernel.
 */
static void
change_date(void)
{
	int	ret;
	struct timeval  tp;

	ret = gettimeofday(&tp, NULL);
	assert(ret == 0);

	tp.tv_usec++;
	ret = settimeofday(&tp, NULL);
	assert(ret == 0);
}

/*
 * The helper thread runs in a loop changing the time and
 * forcing wakeups every 2 seconds.
 */
static void *
helper_thread(void *data)
{
	int	exit;
	struct	timespec ts = {2, 0};

	debug_log("Helper thread started ...\n");

	while (1) {
		pthread_mutex_lock(&exitLock);
		pthread_cond_reltimedwait_np(&exitCond, &exitLock, &ts);
		exit = terminated;
		pthread_mutex_unlock(&exitLock);

		if (exit) {
			break;
		}

		change_date();
		trigger_wakeup();
		debug_log("Time changed and force wakeup issued\n");
	}

	debug_log("Helper thread exiting ...\n");

	pthread_exit(0);
}

static void
stop_threads(void)
{
	pthread_mutex_lock(&exitLock);
	terminated = 1;
	pthread_cond_broadcast(&exitCond);
	pthread_mutex_unlock(&exitLock);
}

static void
run_tests(void)
{
	pthread_t	pollThread = -1;
	pthread_t	helperThread = -1;
	int		ret;

	ret = pthread_create(&helperThread, NULL, helper_thread, NULL);

	if (ret != 0) {
		(void) printf("Failed to create date thread: %s",
		    strerror(ret));
		exit(-1);
	}

	ret = pthread_create(&pollThread, NULL, poll_thread, NULL);

	if (ret != 0) {
		(void) printf("Failed to create poll thread: %s",
		    strerror(ret));
		exit(-1);
	}

	pthread_join(pollThread, NULL);
	stop_threads();
	pthread_join(helperThread, NULL);
}

int
main(int argc, char * const argv[])
{
	int	c;

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		default:
			break;
		}
	}

	/*
	 * We need to be root to change the system time
	 */
	if (getuid() != 0 && geteuid() != 0) {
		(void) printf("%s must be run as root\n", argv[0]);
		exit(-1);
	}

	run_tests();

	exit(0);
}
