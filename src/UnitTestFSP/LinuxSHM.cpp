#include "../FSP_Impl.h"

#define SHM_NAME "/trywslsharedmemory"
#define SHM_SIZE (1024*1024*4)

// Usage 1: shared memory client
void client(char *);

// Usage 2: shared memory server
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


void server()
{
	int hShm = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0777);
	char *buf;
	int r;
	if (hShm < 0)
	{
		perror("Cannot open the shared memory for read/write in server");
		exit(-1);
	}

	r = ftruncate(hShm, SHM_SIZE);
	if (r < 0)
	{
		perror("Cannot set the size of the new created shared memory object");
		exit(-1);
	}

	buf = (char *)mmap(NULL, SHM_SIZE,  PROT_READ | PROT_WRITE, MAP_SHARED, hShm, 0);
	if (buf == NULL)
	{
		perror("Cannot map the shared memory in server");
		exit(-1);
	}
	close(hShm);

	// test the first byte
	while(buf[0] == 0)
		sleep(1);

	printf("String passed via the shared memory: %s\n", buf);
	munmap(buf, SHM_SIZE);
	shm_unlink(SHM_NAME);
}



void client(char *msg)
{
	int hShm = shm_open(SHM_NAME, O_RDWR, 0777);

	char *buf;
	int r;
	if (hShm < 0)
	{
		perror("Cannot open the shared memory for read/write in server");
		exit(-1);
	}

	buf = (char *)mmap(NULL, SHM_SIZE,  PROT_READ | PROT_WRITE, MAP_SHARED, hShm, 0);
	if (buf == NULL)
	{
		perror("Cannot map the shared memory in server");
		exit(-1);
	}
	close(hShm);

	strncpy(buf, msg, SHM_SIZE);

	munmap(buf, SHM_SIZE);
}
