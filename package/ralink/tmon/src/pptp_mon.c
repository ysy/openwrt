#include <stdio.h>
#include <string.h>

int find_user(char * ip, char * out_user)
{
	char path[100];
	strcpy(out_user, "unknow");
	sprintf(path, "/tmp/%s.user", ip);
	FILE * fp = fopen(path, "r");
	
	if (fp == NULL)
		return -1;
	fgets(out_user, 100, fp);
	fclose(fp);
	return 0;
}

int find_rx_tx(char * ip, char * out_tx, char * out_rx)
{
	char buf[1024];
	char iface[20];
	char rx[100];
	char tx[100];
	char ptp[100];

	FILE * fp = fopen("/tmp/ifconfig.txt", "r");
	char * p = NULL;
	while(fgets(buf, 1024,fp) != NULL) 
	{
		if (buf[0] != ' ' )
		{
			p = strtok(buf, " ");
			strcpy(iface, p);
			continue;
		}

		if (strncmp(iface, "ppp", 3 ) )
			continue;

		if ( (p = strstr(buf, "P-t-P:")) != NULL )
		{
			p  = strtok(p, " ");
			p  = strtok(p, ":");
			p = strtok(NULL, ":");
			strcpy(ptp, p);
		} else if ( (p=strstr(buf, "TX bytes:")) != NULL) 
		{
			 p = strtok(p+4, " ");
			 p = strtok(p, ":");
			 p = strtok(NULL, ":");
			 strcpy(tx, p);

			 p = strstr(buf, "RX bytes:");
			 p = strtok(p+4, " "); 
			 p = strtok(p, ":");
                         p = strtok(NULL, ":");
			 strcpy(rx, p);

			if (!strcmp(ptp, ip)) 
                        {
                                strcpy(out_tx, tx);
                                strcpy(out_rx, rx);
                                fclose(fp);
                                return 0;
                        }

		} /*else if ( (p=strstr(buf, "TX packets:")) != NULL) 
		{
			 p = strtok(p+4, " ");
			 p = strtok(p, ":");
			 p = strtok(NULL, ":");
			strcpy(tx, p);
			if (!strcmp(ptp, ip)) 
			{
				strcpy(out_tx, tx);
				strcpy(out_rx, rx);
				fclose(fp);
				return 0;
			}
		}*/
	}
	fclose(fp);
	return -1;
}

int main()
{
	char buf[1024];
	system("LC_ALL=C ifconfig > /tmp/ifconfig.txt");
	char * ip = NULL;
	char  tx[100], rx[100], user[100];
	FILE * fp = fopen("/tmp/pptp_ip.txt", "r");
	FILE * fp_out = fopen("/tmp/pptp_stat.txt", "w");
	if (fp == NULL)
		return;
	while(fgets(buf, 1024, fp))
	{
		buf[strlen(buf)-1] = '\0';
		fprintf(fp_out, "%s ", buf);
		ip = strtok(buf, " ");
		if ( find_rx_tx(ip, tx, rx) == 0 )
		{
			find_user(ip, user);
			fprintf(fp_out, "%s %s %s\n", tx, rx, user);
		}
	}
	fclose(fp_out);
	fclose(fp);
}
