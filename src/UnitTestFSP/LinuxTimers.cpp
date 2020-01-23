#include "../FSP_Impl.h"
#include <pthread.h>

// Link with -lrt  -pthread.
// static void print_siginfo(siginfo_t *si)
// {
//     timer_t *tidp;
//     int overrun;

//     tidp = (timer_t *)si->si_value.sival_ptr;

//     printf("    sival_ptr = %p; ", si->si_value.sival_ptr);
//     printf("    *sival_ptr = 0x%lx\n", (long) *tidp);

//     overrun = timer_getoverrun(*tidp);
//     if (overrun == -1)
//         printf("Failed to run timer_getoverrun");
//     else
//         printf("    overrun count = %d\n", overrun);
// }

static void mycallback(__sigval_t v)
{
    // printf("Argument number: %d\n", v.sival_int);
    printf("Command line: %s\n", ((char **)v.sival_ptr)[0]);
}


// SIGRTMIN: minimum user defined signal send to user process
int main(int argc, char *argv[])
{
    struct sigevent sigev;
    timer_t timerid;
    struct itimerspec its;
    pthread_attr_t tattr;

    pthread_getattr_default_np(&tattr);

    sigev.sigev_notify = SIGEV_THREAD;
    sigev.sigev_signo = SIGRTMIN;
    // sigev.sigev_value.sival_int = argc;
    sigev.sigev_value.sival_ptr = argv;
    sigev.sigev_notify_function = mycallback;   // ;print_siginfo;
    sigev.sigev_notify_attributes = &tattr;     // inherit attributes of the parent thread

    // Or with CAP_WAKE_ALARM capability, to set a timer against CLOCK_BOOTTIME_ALARM?
    // it is assumed that the clock is still while system is suspended, CLOCK_BOOTTIME (since Linux 2.6.12)
    int k = timer_create(CLOCK_MONOTONIC, &sigev, &timerid);
    if (k < 0)
    {
        printf("Error on timer_create\n");
        exit(-1);
    }

    printf("Timer created, id = %p\n", timerid);

    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 500000000;   // 1.5 seconds
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;
    //^ periodic timer

    if (timer_settime(timerid, 0, &its, NULL) == -1)
    {
        printf("Error on timer_settime\n");
        exit(-1);
    }
    printf("Timer started.\n");

    sleep(5);    // not in milli-seconds, but seconds

    exit(0);
}