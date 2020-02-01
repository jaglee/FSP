// Only workd when cygserver started, export CYGWIN=server and cygwin shell executed in Administrator priviledge
// Cannot stat the message queue: Permission denied?
#include "../FSP_Impl.h"
#include <sys/msg.h>

ALIGN(sizeof(long long))
const char $_FSP_KEY[9] = "xFSP_KEY";


struct typed_msg
{
    long type;
    char msg[12];
};

#define FSP_MQ_KEY      (*(uint64_t *)($_FSP_KEY))
#define FSP_MSG_TYPE    18003

// link with -lrt
// Usage 1: message queue client: LinuxMq message
void client(char *);

// Usage 2: message queue server: LinuxMq
void server();

static key_t mqKey;

int main(int argc, char *argv[])
{
    mqKey = ftok(argv[0], FSP_MQ_KEY);
    // mqKey = (key_t)FSP_MQ_KEY;
	if(argc < 2)
		server();
	else if(argc == 2)
		client(argv[1]);
	else
		printf("Usage: %s [message]\n", argv[0]);

	return 0;
}



void server()
{
    int msqid = msgget(mqKey, IPC_CREAT | IPC_EXCL | O_RDONLY);
    if(msqid < 0)
    {
        msqid = msgget(mqKey, O_RDONLY);
        if(msqid < 0)
        {
            perror("Cannot abtain the XSI message queue for read");
            exit(-1);
        }
    }
    printf("Message queue id = %d\n", msqid);

    struct typed_msg msgbuf;    
    int r = (int)msgrcv(msqid, & msgbuf, sizeof(msgbuf.msg), 0, MSG_NOERROR); // | IPC_NOWAIT FSP_MSG_TYPE
    if(r < 0)
    {
        printf("Error number = %d, %d\n", errno, r);
        perror("Cannot receive the message");
        msgctl(msqid, IPC_RMID, NULL);
        exit(-1);
    }

    printf("Message received length = %d: %s\n", (int)r, msgbuf.msg);
}



void client(char *msg)
{
    int msqid = msgget(mqKey, O_WRONLY);
    if(msqid < 0)
    {
        perror("Cannot abtain the XSI message queue for send");
        exit(-1);
    }

    struct msqid_ds ds;
    if(msgctl(msqid, IPC_STAT, &ds) != 0)
    {
        perror("Cannot stat the message queue");
        exit(-1);
    }
    printf("Access mode: %d\n", ds.msg_perm.mode);

    struct typed_msg msgbuf;
    size_t n = min(strlen(msg) + 1, sizeof(msgbuf.msg));
    msgbuf.type = FSP_MSG_TYPE;
    strncpy(msgbuf.msg, msg, n);

    int r = msgsnd(msqid, &msgbuf, n, IPC_NOWAIT);
    if(r < 0)
    {
        perror("Cannot send the message");
        msgctl(msqid, IPC_RMID, NULL);
        exit(-1);
    }
}
