#include "../FSP_Impl.h"
#include <ctype.h>

#define MAX_THREAD_NO 20


/* Used as argument to thread_start() */
struct thread_info
{
    pthread_t thread_id;        /* ID returned by pthread_create() */
    int       thread_num;       /* Application-defined thread # */
    char     *argv_string;      /* From command-line argument */
};


static void *
thread_start(void *arg)
{
	struct thread_info *tinfo = (struct thread_info *)arg;
	char *uargv, *p;

	printf("Thread %d: top of stack near %p; argv_string=%s\n", tinfo->thread_num, &p, tinfo->argv_string);

	uargv = strdup(tinfo->argv_string);
    if (uargv == NULL)
	{
		perror("Cannot call strdup");
		return 0;
	}

	for (p = uargv; *p != '\0'; p++)
		*p = toupper(*p);

	return uargv;
}


int main(int argc, char *argv[])
{
	unsigned long n;
	char *p;
	if(argc < 2 || (n = strtoul(argv[1], &p, 10)) == 0 || *p != '\0' || n > MAX_THREAD_NO)
	{
		printf("Usage: %s <number(which should be no greater than %d) of threads to create>\n", argv[0], MAX_THREAD_NO);
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

	//r = pthread_attr_setstacksize(&attr, 4096);
	//if (r != 0)
	//{
	//	// CYGWIN: error number? #define EINVAL          22
	//	printf("pthread_attr_setstacksize returned %d\n", r);
	//	exit(-1);
	//}

    struct thread_info *tinfo = (struct thread_info *)calloc(n, sizeof(struct thread_info));
    if (tinfo == NULL)
	{
		perror("Cannot allocating enough memory for creating threads.");
		exit(-1);
	}

	printf("Ready. Now to create the threads.\n");
	for(register int i = 0; i < n; i++)
	{
		tinfo[i].thread_num = i + 1;
		tinfo[i].argv_string = argv[1];
		r = pthread_create(&tinfo[i].thread_id, &attr, &thread_start, &tinfo[i]);
		if(r != 0)
		{
			printf("pthread_create returned %d\n", r);
			perror("Cannot create the thread");
			exit(-1);
		}
	}

	r = pthread_attr_destroy(&attr);

	void *res;
	for(register int i = 0; i < n; i++)
	{
        r = pthread_join(tinfo[i].thread_id, &res);
        if (r != 0)
		{
			perror("Calling pthread_join error");
			exit(-1);
		}

		printf("Joined with thread %d; returned value was %s\n", tinfo[i].thread_num, (char *) res);
		free(res);      /* Free memory allocated by thread */
    }

	printf("Press <Enter> to exit...");
	getchar();
	free(tinfo);
	exit(0);
}
