// AF_UNIX, which is POSIX name of AF_LOCAL and AF_FILE, workable in WSLv1
#include "../FSP_Impl.h"
#include <sys/un.h>

#define LOCAL_FILE_PATH "/tmp/FlexibleSessionProtocolMQ"

// Usage 1: AF_UNIX socket client: LinuxSocket message
void client(char *);

// Usage 2: AF_UNIX socket server: LinuxSocket
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



// While SOCK_SEQPACKET
/* Sequenced, reliable, connection-based, datagrams of fixed maximum length.  */
// SOCK_DGRAM is usually implemented reliable and sequenced in Linux
void server()
{
    struct sockaddr_un addr;
    int sd;
    sd = socket(AF_UNIX, SOCK_DGRAM, 0); // SOCK_SEQPACKET need listen and accept
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

	octet buffer[MAX_CTRLBUF_LEN];
	socklen_t szAddr = sizeof(struct sockaddr_un);
	int	nRead = (int)recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &szAddr);
	printf("%d octets read\n", nRead);
	if(nRead > 0)
		printf("Message received: %s\n", buffer);
	else
		perror("Receive error");
	close(sd);
	// unlink(addr.sun_path);
}


void client(char *msg)
{
    struct sockaddr_un addr;
    int sd;

	sd = socket(AF_UNIX, SOCK_DGRAM, 0); // SOCK_SEQPACKET need listen and accept
	if(sd < 0)
	{
		perror("Cannot create AF_UNIX socket for sending");
		exit(-1);
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOCAL_FILE_PATH, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;

	int nSent = (int)sendto(sd, msg, strlen(msg) + 1, 0, (struct sockaddr*)&addr, sizeof(addr));
	if(nSent >= 0)
		printf("%d octets sent\n", nSent);
	else
		perror("Send error");
	close(sd);
}
