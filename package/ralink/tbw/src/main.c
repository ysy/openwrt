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

#define OPENWRT
 
 #define BANDS_COUNT  (10)
char * priomap = "5 6 6 6 5 6 4 4 5 5 5 5 5 5 5 5";

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


#ifndef OPENWRT
	strcpy(wan_iface, "wlan0");
	strcpy(lan_iface, "eth0");
#endif
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

void set_bw_ip(const char * ip,  int ip_idx, const char * down_limit, const char * up_limit);

void init_iface_qdisc()
{
	RUN_CMD("tc qdisc del dev %s root", lan_iface);
	RUN_CMD("tc qdisc del dev %s root", wan_iface);
	RUN_CMD("tc qdisc add dev %s root handle 1: htb default 2", lan_iface);
	RUN_CMD("tc qdisc add dev %s root handle 1: htb default 2", wan_iface);
}

#define DOWN_HANDLE  (0x1000)
#define UP_HANDLE    (0x2000)
void set_bw_ip(const char * ip,  int ip_idx, const char * down_limit, const char * up_limit);

static FILE * fp_cmd = NULL;
void set_bw(char * iprange, const char * down_limit, const char * up_limit)
{
	char ip_start[30];
	char ip_end[30];
	char ip_sub[30];
	int start_idx, end_idx;
	char * p = strtok(iprange, "-");
	if (p == NULL)
		return;	
	strcpy(ip_start, p);
	p = strtok(NULL, "-");
	if (p == NULL)
		return;
	strcpy(ip_end, p);

	p = strrchr(ip_start,  '.');
	start_idx = atoi(p+1);
	p = strrchr(ip_end, '.');
	end_idx = atoi(p+1);
	*p = 0;
	strcpy(ip_sub, ip_end);
	*p = '.';

	LOG("start: %s end: %s start_idx=%d end_idx =%d sub:%s", ip_start, ip_end, start_idx, end_idx, ip_sub);

	int i = 0;

	char ip[30];
	for (i=start_idx; i<=end_idx; i++) 
	{
		sprintf(ip, "%s.%d", ip_sub, i);
		set_bw_ip(ip, i, down_limit, up_limit);
	}
}

void set_prio(const char * iprange, const char * portrange, const char * prio)
{
	RUN_CMD("iptables -t mangle -A PREROUTING -p tcp --dport %s -m iprange --src-range %s \
			-j MARK --set-mark %s", portrange,  iprange, prio);

	RUN_CMD("iptables -t mangle -A POSTROUTING -p tcp --sport %s -m iprange --dst-range %s \
			-j MARK --set-mark %s", portrange,  iprange, prio);

	RUN_CMD("iptables -t mangle -A PREROUTING -p udp --dport %s -m iprange --src-range %s \
			-j MARK --set-mark %s", portrange,  iprange, prio);

	RUN_CMD("iptables -t mangle -A POSTROUTING -p udp --sport %s -m iprange --dst-range %s \
			-j MARK --set-mark %s", portrange,  iprange, prio);
}

void set_bw_ip(const char * ip,  int ip_idx, const char * down_limit, const char * up_limit)
{
	//idx++;
	//add iptables mark
	int idx = ip_idx + 10;
	if (ip_idx < 0)
		idx = 2;

	int i = 0;
	if (strcmp(down_limit, "0") )
	{			
		//limit download, which set tc on lan interface
		fprintf(fp_cmd, "class add dev %s parent 1: classid 1:%x htb rate %s quantum 1500\n", 
					lan_iface, idx, down_limit);

		fprintf(fp_cmd,"qdisc add dev %s parent 1:%x  handle %x: prio bands 10 priomap %s\n",
					lan_iface, idx, idx, priomap);
		
		if (ip_idx > 0)
			fprintf(fp_cmd,"filter add dev %s parent 1: protocol ip prio 1 \
					u32 match ip dst %s/32 flowid 1:%x\n", 
					lan_iface, ip,  idx); 

		for (i=1; i<=BANDS_COUNT; i++) 
		{
			fprintf(fp_cmd, "filter add dev %s parent %x: protocol ip prio 1 \
				handle 0x%04x fw classid %x:%02x\n", 
				lan_iface, idx, i, idx, i); 
		}
	}
	
	if (strcmp(up_limit, "0")) 
	{
		//limit upload, which set tc on wan interface
		fprintf(fp_cmd, "class add dev %s parent 1: classid 1:%x htb rate %s quantum 1500\n", 
					wan_iface, idx, up_limit);
						
		fprintf(fp_cmd,"qdisc add dev %s parent 1:%x handle %x:  prio bands 10 priomap %s\n",
					wan_iface, idx, idx, priomap);

		if (ip_idx > 0 )
			fprintf(fp_cmd,"filter add dev %s parent 1: protocol ip prio 1 \
					u32 match ip src %s/32 flowid 1:%x\n", 
					wan_iface, ip,  idx); 

		for (i=1; i<=BANDS_COUNT; i++) 
		{
			fprintf(fp_cmd, "filter add dev %s parent %x: protocol ip prio 1 \
				handle 0x%04x fw classid %x:%02x\n", 
				wan_iface, idx, i, idx, i); 
		}
	}
}


void reload_config()
{
	char buf[1024];
	int len =0; 
	FILE * fp = NULL;
	
	decide_iface();
	clear_iptables_mark();
	init_iface_qdisc();
#ifdef OPENWRT
	fp = fopen("/etc/tbw.conf", "r");
#else
	fp = fopen("./tbw.conf", "r");
#endif

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
	
	fp_cmd = fopen("/tmp/tbw_cmd", "w");
	while (fgets(buf,1024, fp))
	{
		len = strlen(buf);
		while(isspace(buf[len-1]) )
		{
			buf[len-1] = '\0';
			len--;
		}
		char * iprange = strtok(buf, " ");
		char * down_limit = strtok(NULL, " ");
		char * up_limit = strtok(NULL, " ");
		char * enabled = strtok(NULL, " ");
		if (enabled != NULL && enabled[0] == '0')
			continue;
		if (iprange != NULL && down_limit != NULL 
			&& up_limit != NULL) 
		{
			set_bw(iprange, down_limit, up_limit);
		}
	}

	set_bw_ip("dummy", -1, "100mbit", "100mbit");
	fclose(fp_cmd);
	RUN_CMD("tc -b /tmp/tbw_cmd");
	fclose(fp);


#ifdef OPENWRT
	fp = fopen("/etc/prio.conf", "r");
#else
	fp = fopen("./prio.conf", "r");
#endif

	if (fp == NULL)
	{
		LOG("ERROR: /etc/prio.conf dose not exists");
		exit(-1);
	}

	while (fgets(buf,1024, fp))
	{
		len = strlen(buf);
		while(isspace(buf[len-1]) )
		{
			buf[len-1] = '\0';
			len--;
		}
		char * iprange = strtok(buf, " ");
		char * portrange = strtok(NULL,  " ");
		char * prio = strtok(NULL, " ");
		char * enabled = strtok(NULL, " ");


		if (enabled != NULL && enabled[0] == '0')
			continue;
		if (iprange != NULL && portrange != NULL 
			&& prio != NULL) 
		{
			char * p = strstr(portrange, "-");
			if (p != NULL)
				*p = ':';
			set_prio(iprange, portrange, prio);
		}
	}

}

int main(int argc,  char * argv[])
{  
	INIT_LOG("TBW");
	LOG("Bandwith control program");
	reload_config();
	return 0;
}
