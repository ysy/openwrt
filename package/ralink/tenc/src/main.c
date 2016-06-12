#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int ikey = 0x1234;

int main(int argc,  char * argv[])
{
	unsigned char key[128];
	unsigned char buf[1024];
	unsigned char enc_en = 0;		
	int len,i,key_pos,ret;
	int in_fd = fileno(stdin);
	int out_fd = fileno(stdout);

	ret = system("uci get system.config_encrypt.enabled | grep 1 > /dev/null");
	if (ret == 0 ) 
		enc_en = 1;

	if (enc_en)
	{
		srand(ikey);
		for (i=0; i<sizeof(key); i++)
		{
			key[i] = rand() % 256;
		}
	}
	
	key_pos = 0;
	while(1)
	{
		len = read(in_fd, buf, 1024);
		if (len <= 0 ) 
			break;
		if (enc_en)
		{
			for (i=0; i<len; i++)
			{
				buf[i] = buf[i] ^ key[key_pos++ % sizeof(key)];
			}
		}

		write(out_fd, buf, len);
	}
	return 0;
}
