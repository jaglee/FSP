#include "../FSP_Impl.h"

#define MQ_NAME "/trywslmq"
#define MSG_SIZE 424

// link with -lrt
// Usage 1: message queue client: LinuxMq message
void client(char *);

// Usage 2: message queue server: LinuxMq
void server();


int main(int argc, char *argv[])
{
	if(argc < 2)
		server();
	else if(argc == 2)
		client(argv[1]);
	else
		printf("Usage: %s [message]\n", argv[0]);

	return 0;
}



// Cannot fetch message from the queue, error number = 90
void mycallback(sigval_t parm)
{
    mqd_t mqdes = (mqd_t)parm.sival_int;
	printf("Parameter mail descriptor: %d\n", mqdes);

	char linebuf[MSG_SIZE];
	unsigned int  msg_pri;
	ssize_t sz = mq_receive(mqdes, linebuf, MSG_SIZE, &msg_pri);
	if (sz < 0)
	{
		perror("Cannot fetch message from the queue");
		exit(-1);
	}
	// while mq_timereceive set the time-out for block operation
	printf("Priority %u, length = %d, message received: %s\n", msg_pri, sz, linebuf);

	mq_unlink(MQ_NAME);
}



/*
	   EACCES The queue exists, but the caller does not have permission to
			  open it in the specified mode.

	   EACCES name contained more than one slash.

	   EEXIST Both O_CREAT and O_EXCL were specified in oflag, but a queue
			  with this name already exists.

	   EINVAL name doesn't follow the format in mq_overview(7).

	   EINVAL O_CREAT was specified in oflag, and attr was not NULL, but
			  attr->mq_maxmsg or attr->mq_msqsize was invalid.  Both of
			  these fields must be greater than zero.  In a process that is
			  unprivileged (does not have the CAP_SYS_RESOURCE capability),
			  attr->mq_maxmsg must be less than or equal to the msg_max
			  limit, and attr->mq_msgsize must be less than or equal to the
			  msgsize_max limit.  In addition, even in a privileged process,
			  attr->mq_maxmsg cannot exceed the HARD_MAX limit.  (See
			  mq_overview(7) for details of these limits.)

	   EMFILE The per-process limit on the number of open file and message
			  queue descriptors has been reached (see the description of
			  RLIMIT_NOFILE in getrlimit(2)).

	   ENAMETOOLONG
			  name was too long.

	   ENFILE The system-wide limit on the total number of open files and
			  message queues has been reached.

	   ENOENT The O_CREAT flag was not specified in oflag, and no queue with
			  this name exists.

	   ENOENT name was just "/" followed by no other characters.

	   ENOMEM Insufficient memory.

	   ENOSPC Insufficient space for the creation of a new message queue.
			  This probably occurred because the queues_max limit was
			  encountered; see mq_overview(7).

			  */

void server()
{
    struct sigevent sev;
    mqd_t mqdes;
	struct mq_attr mqa;

	mqa.mq_flags = 0;       /* Flags (ignored for mq_open()) */
	mqa.mq_maxmsg = 5;      /* Max. # of messages on queue */
	mqa.mq_msgsize = MSG_SIZE;     /* Max. message size (bytes) */
	mqa.mq_curmsgs = 0;     /* # of messages currently in queue */
	mqdes = mq_open(MQ_NAME, O_RDONLY | O_CREAT, 0777, &mqa);

    if (mqdes == (mqd_t) -1)
	{
		printf("To read %s:\n", MQ_NAME);
		perror("cannot create open the message queue");
		exit(-1);
	}

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = mycallback;
    sev.sigev_notify_attributes = NULL;
	sev.sigev_value.sival_int = mqdes;
	// sev.sigev_value.sival_ptr = (void *)mqdes;   // we assume the descriptor is pointer compatible
    if (mq_notify(mqdes, &sev) == -1)
	{
		perror("Cannot register the asynchronous message queue event handler");
		exit(-1);
	}

	pause();
}



void client(char *msg)
{
    mqd_t mqdes;

    mqdes = mq_open(MQ_NAME, O_WRONLY);
    if (mqdes == (mqd_t) -1)
	{
		printf("Writing to %s\n:", MQ_NAME);
		perror("cannot open the message queue");
		exit(-1);
	}

	// terminating zero is sent together with the content
	printf("We want send %s to the peer\n", msg);
	mq_send(mqdes, msg, strlen(msg) + 1, 0);
	// or with mq_timedsend
}