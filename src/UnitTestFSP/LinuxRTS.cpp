#include "../FSP_Impl.h"
#include <dirent.h>

// POSIX real-time signals.
// The range of supported real-time signals is defined by the macros SIGRTMIN and SIGRTMAX
#define		SIG_FSP		SIGRTMIN

// Usage 1: signal-event client
void client(pid_t);

// Usage 2: shared memory server
void server();


int main(int argc, char *argv[])
{
	if(argc == 1)
		server();
	else if(argc == 2)
		client((pid_t)atoi(argv[1]));
	else
		printf("Usage: %s [pid]\n", argv[0]);

	return 0;
}


/*
   This function receives the signal number as its first argument,
   a pointer to a siginfo_t as its second argument
   and a pointer to a ucontext_t (cast to void *) as its third argument.
   (Commonly, the handler function doesn't make any use of the third argument.
   See getcontext(3) for further information about ucontext_t.) 
*/
void myaction(int signo, siginfo_t *info, void *pContext)
{
// struct siginfo_t {
//    int      si_signo;    /* Signal number */
//    int      si_errno;    /* An errno value */
//    int      si_code;     /* Signal code */
//    int      si_trapno;   /* Trap number that caused
//                             hardware-generated signal
//                             (unused on most architectures) */
//    pid_t    si_pid;      /* Sending process ID */
//    uid_t    si_uid;      /* Real user ID of sending process */
//    int      si_status;   /* Exit value or signal */
//    clock_t  si_utime;    /* User time consumed */
//    clock_t  si_stime;    /* System time consumed */
//    sigval_t si_value;    /* Signal value */
//    int      si_int;      /* POSIX.1b signal */
//    void    *si_ptr;      /* POSIX.1b signal */
//    int      si_overrun;  /* Timer overrun count; POSIX.1b timers */
//    int      si_timerid;  /* Timer ID; POSIX.1b timers */
//    void    *si_addr;     /* Memory location which caused fault */
//    long     si_band;     /* Band event (was int in
//                             glibc 2.3.2 and earlier) */
//    int      si_fd;       /* File descriptor */
//    short    si_addr_lsb; /* Least significant bit of address
//                             (since kernel 2.6.32) */
//}
	printf("Signal #%d received, siginfo:\n", signo);
	printf("  si_signo = %d", info->si_signo);
	printf("  si_errno = %d\n", info->si_errno);
	printf("  si_code = %d\n", info->si_code);
	printf("  si_pid = %d\n", info->si_pid);
	printf("  si_uid = %d\n", info->si_uid);
	// getcontext(pContext);
}


//
//
/**
  pause () causes the calling process (or thread) to sleep
  until a signal is delivered that either terminates the process
  or causes the invocation of a signal-catching function.
  pause () returns only when a signal was caught and the signal-catching function returned
  */
// 
void server()
{
	struct sigaction act;
	int r;

	// On some architectures a union is involved: do not assign to both sa_handler and sa_sigaction. 
    //void     (*sa_handler)(int);
    //void     (*sa_sigaction)(int, siginfo_t *, void *);
	act.sa_sigaction = myaction;
	sigemptyset(& act.sa_mask);
	act.sa_flags = SA_NODEFER | SA_SIGINFO;
	// The sa_restorer element is obsolete and should not be used. POSIX does not specify a sa_restorer element.

	r = sigaction(SIG_FSP, &act, NULL);
	if (r < 0)
	{
		perror("Cannot set the action to handle the signal/event");
		exit(-1);
	}
	pause();
}


static
bool IsProcessAlive(pid_t idSrcProcess)
{
	// PROCESS_QUERY_LIMITED_INFORMATION
	const int START_POSITON = 6;
	char procName[] = "/proc/000000000";
	// implement itoa locally
	uint32_t r = (uint32_t)idSrcProcess;
	register int i = START_POSITON + 8;
	while(i >= START_POSITON)
	{
		procName[i] = '0' + (char)(r % 10);
		r = r / 10;
		i--;
		if(r == 0)
			break;
	}
	if(i >= START_POSITON)
		memmove(procName + START_POSITON, procName + i + 1, START_POSITON + 9 - i);	// include the terminating '\0'
	printf("To find process file %s\n", procName);
	// // opendir() is present on SVr4, 4.3BSD, and specified in POSIX.1-2001.
	// DIR * dirp = opendir(procName);
	// if (dirp == NULL)
	// 	return false;
	// // closedir(dirp);
	int fd = open(procName, O_RDONLY);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}


/*
	Starting with version 2.2, Linux supports real-time signals as
       originally defined in the POSIX.1b real-time extensions (and now
       included in POSIX.1-2001).  The range of supported real-time signals
       is defined by the macros SIGRTMIN and SIGRTMAX.  POSIX.1-2001
       requires that an implementation support at least _POSIX_RTSIG_MAX (8)
       real-time signals.
	   */


/*

	EAGAIN

	The limit of signals which may be queued has been reached. (See signal(7) for further information.)

	EINVAL

	sig was invalid.

	EPERM

	The process does not have permission to send the signal to the receiving process. For the required permissions, see kill(2).

	ESRCH

	No process has a PID matching pid. 
*/
void client(pid_t pid)
{
	sigval_t value;
	int r;
	value.sival_int = 18003;
	if (IsProcessAlive(pid))
		printf("The process %d is alive.\n", pid);
	else
		printf("Cannot find the process %d in /proc directory.\n", pid);
	r = sigqueue(pid, SIG_FSP, value); 
	if (r < 0)
		perror("Calling sigqueue failed");
}
