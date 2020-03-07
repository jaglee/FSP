// AF_UNIX, which is POSIX name of AF_LOCAL and AF_FILE, workable in WSLv1
#include "../FSP_Impl.h"
#include <ctype.h>
#include <sys/un.h>

#define LOCAL_FILE_PATH "/tmp/FlexibleSessionProtocolMQ"
#define MAX_ERRORS		5

/* Used as argument to thread_start() */
struct thread_info
{
    pthread_t	thread_id;	/* ID returned by pthread_create() */
    int			sd;       	/* socket descriptor */
	char		place_holder[MAX_BLOCK_SIZE * MAX_BUFFER_BLOCKS * 8];	// 1GB
};


static void *
thread_start(void *arg)
{
	struct thread_info *tinfo = (struct thread_info *)arg;
	octet buffer[MAX_CTRLBUF_LEN];
	int& sd1 = tinfo->sd;

	printf("Thread id = %lu: top of stack near %p\n"
		   "socket descriptor = %d, info pointer = %p\n"
		   , tinfo->thread_id, buffer
		   , sd1, tinfo);

	int	nRead = (int)recv(sd1, buffer, sizeof(buffer), 0);
	printf("%d octets read\n", nRead);
	if(nRead > 0)
		printf("Message received: %s\n", buffer);
	else
		perror("Receive error");
	putchar('\n');
	shutdown(sd1, SHUT_RDWR);
	close(sd1);

	free(tinfo);
	return NULL;
}


// Usage 1: AF_UNIX socket client: LinuxSeqSock message
void client(char *);

// Usage 2: AF_UNIX socket server: LinuxSeqSock
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



// While SOCK_SEQPACKET is not supported on CYGWIN, SOCK_STREAM is.
void server()
{
    struct sockaddr_un addrIn;
    struct sockaddr_un addr;
    int sd;
    sd = socket(AF_UNIX, SOCK_STREAM, 0); // SOCK_SEQPACKET
	if(sd < 0)
	{
		perror("Cannot create AF_UNIX socket for listening");
		exit(-1);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOCAL_FILE_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	if(bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0)
	{
		int r = 0;
		if(errno == EADDRINUSE)
		{
			if(unlink(addr.sun_path) < 0)
				printf("%s existed but cannot be unlinked.\n", addr.sun_path);
			r = bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
			if(r == 0)
				printf("%s existed but was unlinked and re-bound.\n", addr.sun_path);
		}
		if(r < 0)
		{
			perror("Cannot bind the AF_UNIX socket to the designated path");
			exit(-1);
		}
	}
	// offsetof(struct sockaddr_un, sun_path)+strlen(addr.sun_path)+1
	// When coding portable applications, keep in mind that some implementations have sun_path as short as 92 bytes.

	if(listen(sd, 5) != 0)
	{
		perror("Cannot set the listening queue");
		exit(-1);
	}

	pthread_attr_t attr;
	int r = pthread_attr_init(&attr);
	if (r != 0)
	{
		printf("pthread_attr_init returned %d\n", r);
		perror("Cannot initialize the thread attribute to set");
		exit(-1);
	}


	socklen_t szAddr = sizeof(struct sockaddr_un);
	int sd1;
	int nError = 0;
	while((sd1 = accept(sd, (struct sockaddr*)&addrIn, &szAddr)) != -1)
	{
		struct thread_info *tinfo = (struct thread_info *)malloc(sizeof(struct thread_info));
		if (tinfo == NULL)
		{
			perror("Cannot allocating enough memory for creating threads.");
			nError++;
			if(nError > MAX_ERRORS)
			{
				printf("Too many malloc or pthread_create errors\n");
				exit(-1);
			}
			continue;
		}
		printf("Memory allocated at %p\n", tinfo);

		tinfo->place_holder[MAX_BLOCK_SIZE * MAX_BUFFER_BLOCKS - 1] = 0xA5;
		tinfo->sd = sd1;
		r = pthread_create(&tinfo->thread_id, &attr, &thread_start, tinfo);
		if(r != 0)
		{
			perror("pthread_create error");
			free(tinfo);
			nError++;
		}
		else
		{
			nError = 0;
		}
		//
		if(nError > MAX_ERRORS)
		{
			printf("Too many malloc or pthread_create errors\n");
			exit(-1);
		}
	}

	perror("Cannot incarnating a new socket for accepting message");
	// pthread_attr_destroy(&attr);
	close(sd);
	// unlink(addr.sun_path);
}



void client(char *msg)
{
    struct sockaddr_un addr;
    int sd;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);	// SOCK_SEQPACKET
	if(sd < 0)
	{
		perror("Cannot create AF_UNIX socket for sending");
		exit(-1);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOCAL_FILE_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		perror("Cannot connect to the remote peer");
		exit(-1);
	}

	int nSent = (int)send(sd, msg, strlen(msg) + 1, 0);
	if(nSent >= 0)
		printf("%d octets sent\n", nSent);
	else
		perror("Send error");
	shutdown(sd, SHUT_RDWR);
	close(sd);
}
