/***************************************************************************
 *   Copyright (C) 2004-2006 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <linux/types.h>

#include  "log.h"
 
char * get_string_from_file(const char * path,  char * out_buf)
{
	char buf[1024];
	buf[0] = '\0';
	out_buf[0] = '\0';
	FILE * fp = fopen(path, "r");
	if (fp == NULL)
		return out_buf;

	fgets(buf, 1024, fp);
	fclose(fp);

	int len = strlen(buf);
	while(isspace(buf[len-1]) )
	{
		buf[len-1] = '\0';
		len--;
	}
	strcpy(out_buf, buf);
	return out_buf;
}

static char wan_iface[20];
static char lan_iface[20];

static char cmd[1024];

#define RUN_CMD(fmt, args...) \
	do{  \
		sprintf(cmd, fmt, ##args); \
		system(cmd); \
	} while(0);  
	
		 
void decide_iface()
{
	char proto[20];
	memset(wan_iface, 0, sizeof(wan_iface));
	memset(lan_iface, 0, sizeof(lan_iface));
	system("uci get network.wan.ifname > /tmp/tbw_wanifname.txt");
	get_string_from_file("/tmp/tbw_wanifname.txt", wan_iface);
	system("uci get network.wan.proto > /tmp/tbw_wanifname.txt");
	get_string_from_file("/tmp/tbw_wanifname.txt", proto);
	if (!strncmp(proto, "ppp", 3) )
	{
		sprintf(wan_iface, "%s-wan", proto);
	}
	strcpy(lan_iface, "br-lan");
	LOG("WAN: %s, LAN: %s", wan_iface, lan_iface);
}

void clear_iptables_mark()
{
	char cmd[1024];
	char buf[1024];
	system("iptables-save | grep MARK  > /tmp/iptables_mark.txt");
	FILE * fp = fopen("/tmp/iptables_mark.txt", "r");
	
	if (fp == NULL) 
	{
		LOG("ERROR: error when clear iptables mark");
		exit(-1);
	}
	
	while(fgets(buf, 1024, fp)) 
	{
		if (buf[0] == '-' && buf[1] == 'A') 
		{
			buf[1] = 'D';
			RUN_CMD("iptables -t mangle %s", buf);
			//LOG("iptable cmd: %s", cmd);
		}
	}
	fclose(fp);
}

void init_iface_qdisc()
{
	RUN_CMD("tc qdisc del dev %s root", lan_iface);
	RUN_CMD("tc qdisc del dev %s root", wan_iface);
	RUN_CMD("tc qdisc add dev %s root handle 1: htb", lan_iface);
	RUN_CMD("tc qdisc add dev %s root handle 2: htb", wan_iface);
}

#define DOWN_HANDLE  (0x1000)
#define UP_HANDLE    (0x2000)

static int idx = 0;
void set_bw(const char * iprange, const char * down_limit, const char * up_limit)
{
	idx++;
			 
	//add iptables mark	
	if (strcmp(down_limit, "0"))
	{
		RUN_CMD("iptables -t mangle -A POSTROUTING -m iprange --dst-range %s \
			-j MARK --set-mark %d", iprange, DOWN_HANDLE + idx);
			
		//limit download, which set tc on lan interface
		RUN_CMD("tc class add dev %s parent 1: classid 1:%02x htb rate %s quantum 1500", 
					lan_iface, idx, down_limit);
		
		
		RUN_CMD("tc qdisc add dev %s parent 1:%02x fq_codel",
					lan_iface, idx);
		
		RUN_CMD("tc filter add dev %s parent 1: protocol ip prio 1 \
				handle 0x%04x fw classid 1:%02x", 
				lan_iface, DOWN_HANDLE + idx, idx);
	}
	
	if (strcmp(up_limit, "0")) 
	{
		RUN_CMD("iptables -t mangle -A PREROUTING -m iprange --src-range %s \
		 -j MARK --set-mark %d", iprange, UP_HANDLE + idx);
			
		//limit upload, which set tc on wan interface
		RUN_CMD("tc class add dev %s parent 2: classid 2:%02x htb rate %s quantum 1500", 
					wan_iface, idx, up_limit);
						
		RUN_CMD("tc qdisc add dev %s parent 2:%02x fq_codel",
					wan_iface, idx);
		RUN_CMD("tc filter add dev %s parent 2: protocol ip prio 1 \
				handle 0x%04x fw classid 2:%02x", 
				wan_iface, UP_HANDLE + idx, idx);
	}
}


void reload_config()
{
	char buf[1024];
	int len =0; 
	FILE * fp = NULL;
	
	idx = 0;
	decide_iface();
	clear_iptables_mark();
	init_iface_qdisc();
	fp = fopen("/etc/tbw.conf", "r");
	if (fp == NULL)
	{
		LOG("ERROR: /etc/tbw.conf dose not exists");
		exit(-1);
	}
	
	memset(buf, 0, sizeof(buf));
	if ( fgets(buf, 1024, fp)  == NULL )
	{
		LOG("ERROR: /etc/tbw.conf is empty");
		return;
	}
	
	if (!strncmp(buf, "off", 3))
	{
		LOG("Bandwith control is disabled");
		return;
	}
	
	while (fgets(buf,1024, fp))
	{
		len = strlen(buf);
		while(isspace(buf[len-1]) )
		{
			buf[len-1] = '\0';
			len--;
		}
		const char * iprange = strtok(buf, " ");
		const char * down_limit = strtok(NULL, " ");
		const char * up_limit = strtok(NULL, " ");
		const char * enabled = strtok(NULL, " ");
		if (enabled != NULL && enabled[0] == '0')
			continue;
		if (iprange != NULL && down_limit != NULL 
			&& up_limit != NULL) 
		{
			set_bw(iprange, down_limit, up_limit);
		}
	}
	
	fclose(fp);
}

int main(int argc,  char * argv[])
{  
	INIT_LOG("TBW");
	LOG("Bandwith control program");
	reload_config();
	return 0;
}