#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "md5.h"
#include "files.h"

//#define USE_CHECK_THREAD 1

int good_check();

#ifdef USE_CHECK_THREAD

#include <pthread.h>

void * check_thread(void * arg)
{
	while(1) {
		good_check();
		sleep(60 * 60);
	}
}

void good_checker()
{
	pthread_t tid;
	pthread_create(&tid,NULL,check_thread,NULL);
}

#else
void good_checker()
{
	good_check();
}

#endif
void get_md5_sum(const char * path, char * out_md5)
{
	MD5_CTX ctx;
	unsigned char digest[16];
	char buf[4096];
	int len;

	out_md5[0] = '\0';
	FILE * fp = fopen(path, "rb");
	if (!fp)
		return;

	MD5Init(&ctx);

	while ((len = fread(buf, 1, 4096, fp)) > 0 ) {
		MD5Update(&ctx, buf, len);
	}

	fclose(fp);
	MD5Final(&ctx, digest);
	int i=0;
	for (i=0; i<16; i++) {
		out_md5 += sprintf(out_md5, "%02x", digest[i]);
	}
}

void killall()
{
	system("killall tmon");
	system("iptables -F");
	system("/etc/init.d/pptpd stop");
	system("/etc/init.d/tinyproxy stop");
}

int good_check()
{
	int i =0;
	char md5[40];
	for (i=0; ; i++) {
		if (!md5_files[i].filepath)
			break;
		get_md5_sum(md5_files[i].filepath, md5);
		if (strcmp(md5_files[i].md5, md5))  {
			killall();
			exit(-1);
			return 1;
		}
	}
	return 0;
}
/*
int main()
{
	good_checker();
	while(1) {
		sleep(1);
	}
	return;
}*/
