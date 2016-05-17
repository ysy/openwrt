/***************************************************************************
 *   Copyright (C) 2004-2006 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <pthread.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubus.h>
#include <json-c/json.h>


#include  "log.h"
#include "libxt_ACCOUNT_cl.h"

bool exit_now = false;
static int interval = 10;
static int pass_sec =10;
static bool enabled = true;

static void sig_term(int signr)
{
        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        exit(0);
}

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

static in_addr_t  net_ip;
static pthread_mutex_t lock;
struct ip_acc 
{
	bool  has_data;
	uint32_t pkt_total;
	uint32_t byte_total;	
};


struct ip_speed
{
	uint32_t rx_pkt;
	uint32_t rx_byte;
	uint32_t tx_pkt;
	uint32_t tx_byte;
	uint32_t rx_udp;
	uint32_t rx_icmp;
	uint32_t rx_syn;
	uint32_t tx_udp;
	uint32_t tx_icmp;
	uint32_t tx_syn;
};

struct arp_entry
{
	char mac[22];
};

static struct  ip_acc      acc[256];
static struct  ip_speed  spd[256];

static struct  arp_entry arp[256];
static struct ipt_ACCOUNT_context ctx;

static inline unsigned char get_idx(in_addr_t  ip)
{
	unsigned char * bytes = (unsigned char * ) &ip;
	return bytes[3];
}

const char * json_get_string(json_object * root, const char * key)
{
	const char * str = NULL;
	json_object * child;
	if (json_object_object_get_ex(root, key, &child)) {
		str = json_object_get_string(child);
	}
	return str;
}

int check_iptables()
{
	int ret = 0;	
	char command[256];
	char netip_str[20];
		
	system("uci get network.lan.ipaddr > /tmp/lan_ip_addr.txt");
	get_string_from_file("/tmp/lan_ip_addr.txt", netip_str);
	net_ip = inet_addr(netip_str);
	
	unsigned char * bytes = (unsigned char * ) &net_ip;
	LOG("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
	
	system("/etc/init.d/firewall restart");
	system("iptaccount -h");
	{
		sprintf(command, "iptables  -I FORWARD 1  -j ACCOUNT  --addr %s/24 --tname all", netip_str);
		system(command);
		sprintf(command, " iptables -I FORWARD 1 -p udp -j ACCOUNT --addr %s/24 --tname udp", netip_str);
		system(command);
		sprintf(command, " iptables -I FORWARD 1 -p icmp -j ACCOUNT --addr %s/24 --tname icmp", netip_str);
		system(command);
		sprintf(command, " iptables -I FORWARD 1 -p tcp --syn -j ACCOUNT --addr %s/24 --tname syn", netip_str);
		system(command);		
	}
	return 0;
}

int load_arp()
{
	FILE * fp = fopen("/proc/net/arp", "r");
	char buf[1024];
	fgets(buf, 1024, fp); //skip first line
	char * ip, *mac, *iface;
	int idx;
	while(fgets(buf, 1024, fp))
	{
		ip = strtok(buf, " ");
		strtok(NULL, " ");
		strtok(NULL, " ");
		mac = strtok(NULL, " ");
		strtok(NULL, " ");
		iface = strtok(NULL, " ");
		
		if (strncmp(iface, "br-lan", 6))
			continue;
		idx = get_idx(inet_addr(ip));
		strcpy(arp[idx].mac, mac);
	}
	
	fclose(fp);
	return 0;
}


void refresh_account_data()
{
	bool do_flush = true;
	struct ipt_acc_handle_ip *entry;
	
	memset(spd, 0, sizeof(spd));
	if (ipt_ACCOUNT_read_entries(&ctx, "all", !do_flush))
	{
		LOG("Read failed: %s\n", ctx.error_str);
		ipt_ACCOUNT_deinit(&ctx);
		return EXIT_FAILURE;
	}

	while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
	{
		unsigned idx = get_idx(htonl(entry->ip));
		acc[idx].byte_total += (entry->dst_bytes + entry->src_bytes);
		acc[idx].pkt_total += (entry->dst_packets + entry->src_packets);
		acc[idx].has_data = true;
		
		spd[idx].rx_pkt = (entry->dst_packets + interval-1) /interval;
		spd[idx].rx_byte = entry->dst_bytes /interval;
		spd[idx].tx_pkt  = (entry->src_packets + interval-1) /interval;
		spd[idx].tx_byte = entry->src_bytes /interval;
	}
	
	//ICMP
	if (ipt_ACCOUNT_read_entries(&ctx, "icmp", !do_flush))
	{
		LOG("Read failed: %s\n", ctx.error_str);
		ipt_ACCOUNT_deinit(&ctx);
		return EXIT_FAILURE;
	}

	while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
	{
		unsigned idx = get_idx(htonl(entry->ip));
		spd[idx].rx_icmp = (entry->dst_packets + interval -1) /interval;
		spd[idx].tx_icmp = (entry->src_packets + interval -1) /interval;
	}
	
	//SYN
	if (ipt_ACCOUNT_read_entries(&ctx, "syn", !do_flush))
	{
		LOG("Read failed: %s\n", ctx.error_str);
		ipt_ACCOUNT_deinit(&ctx);
		return EXIT_FAILURE;
	}

	while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
	{
		unsigned idx = get_idx(htonl(entry->ip)); 
		spd[idx].rx_syn =  (entry->dst_packets + interval -1) /interval;
		spd[idx].tx_syn =  (entry->src_packets + interval -1) /interval;
	}
	
	//UDP
	if (ipt_ACCOUNT_read_entries(&ctx, "udp", !do_flush))
	{
		LOG("Read failed: %s\n", ctx.error_str);
		ipt_ACCOUNT_deinit(&ctx);
		return EXIT_FAILURE;
	}

	while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
	{
		unsigned idx = get_idx(htonl(entry->ip));
		spd[idx].rx_udp = (entry->dst_packets + interval -1) /interval;
		spd[idx].tx_udp = (entry->src_packets + interval -1) /interval;
	}
}

void output_account_data()
{
	int i =0;
	FILE * fp = fopen("/tmp/test.html", "w");
	fprintf(fp,  "IP Address\tMAC Address\tTOTAL_PKT\tTOTAL_BYTE\tRX_PKTS\tRX_BYTES\tTX_PKTS\tTX_BYTES\tUDP_RX\tUDP_TX\tICMP_RX\tICMP_TX\tSYN_RX\tSYN_TX\n<br>");
	fprintf(stderr,  "IP Address\tMAC Address\tRX_PKTS\tRX_BYTES\tTX_PKTS\tTX_BYTES\n");
	
	unsigned char * ip = (unsigned char * ) &net_ip;
	for (i=0; i<256; i++)
	{
		if (acc[i].has_data)
		{
			fprintf(fp, "%u.%u.%u.%u\t%s\t", ip[0], ip[1], ip[2], i, arp[i].mac);
			fprintf(fp, "%d\t%d\t", acc[i].pkt_total,  acc[i].byte_total); 
			fprintf(fp, "%d\t%d\t%d\t%d\t", spd[i].rx_pkt, spd[i].rx_byte,  spd[i].tx_pkt, spd[i].tx_byte); 
			fprintf(fp, "%d\t%d\t%d\t%d\t", spd[i].rx_udp, spd[i].tx_udp,  spd[i].rx_icmp, spd[i].tx_icmp); 
			fprintf(fp, "%d\t%d\t", spd[i].rx_syn, spd[i].tx_syn); 
			
			fprintf(stderr, "%u.%u.%u.%u\t%s\t", ip[0], ip[1], ip[2], i, arp[i].mac);
			fprintf(stderr, "%d\t%d\t%d\t%d", spd[i].rx_pkt, spd[i].rx_byte,  spd[i].tx_pkt, spd[i].tx_byte); 							
			
			fprintf(fp, "<br>");
			fprintf(stderr, "\n");
		}
	}
	fclose(fp);
}

static void receive_ubus_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	char *str;
	str = blobmsg_format_json(msg, true);
	LOG("{ \"%s\": %s }\n", type, str);
	json_object * obj =  json_tokener_parse(str);
	
	const char *  cmd = json_get_string(obj, "cmd");
	const char * ip = json_get_string(obj, "ip");
	pthread_mutex_lock(&lock);
	if (!strcmp(cmd, "clear_all")) 
	{
		memset(acc, 0, sizeof(acc));
		memset(spd, 0, sizeof(spd));
	} else if (!strcmp(cmd, "clear") )
	{
		in_addr_t  ip_addr = inet_addr(ip);
		unsigned char idx = get_idx(ip_addr);
		memset(&acc[idx], 0, sizeof(struct  ip_acc));
		memset(&spd[idx], 0, sizeof(struct  ip_speed));
		acc[idx].has_data = true;
	} else if (!strcmp(cmd, "delete") )
	{
		in_addr_t  ip_addr = inet_addr(ip);
		unsigned char idx = get_idx(ip_addr);
		memset(&acc[idx], 0, sizeof(struct  ip_acc));
	} else if (!strcmp(cmd, "stop"))  
	{
		if (enabled)
		{
			enabled = false;	
			memset(acc, 0, sizeof(acc));
		}
	} else if (!strcmp(cmd, "start") )
	{
		if (enabled == false)
		{
			refresh_account_data();
			memset(acc, 0, sizeof(acc));
			enabled = true;
			pass_sec =0;
		}
	} else if (!strcmp(cmd, "set_interval"))
	{
		const char * interval_str = json_get_string(obj, "interval");
		interval = atoi(interval_str);
		pass_sec = 0;
	}
	
	output_account_data();
	pthread_mutex_unlock(&lock);
	json_object_put(obj);
}

void * ubus_loop(void * p)
{
	struct ubus_context *ubus_ctx;
	struct ubus_event_handler listener;
	
	ubus_ctx = ubus_connect(NULL);
	memset(&listener, 0, sizeof(listener));
	listener.cb = receive_ubus_event;
	ubus_register_event_handler(ubus_ctx, &listener, "tmon.*");
	
	 uloop_init();
        ubus_add_uloop(ubus_ctx);
        uloop_run();
}

void account_loop(void * p)
{
	while(1)
	{
		pthread_mutex_lock(&lock);
		if (pass_sec >= interval)
		{
			pass_sec = 0;
			if (enabled)
			{
				load_arp();
				refresh_account_data();
				output_account_data();	
			}	
		}
		pass_sec++;
		pthread_mutex_unlock(&lock);
		sleep(1);
	}
	return 0;
}

static pthread_t ubus_thread;

int main(int argc,  char * argv[])
{
	 if (signal(SIGTERM, sig_term) == SIG_ERR)
        {
                printf("can't install signal handler for SIGTERM\n");
                exit(-1);
        }
        if (signal(SIGINT, sig_term) == SIG_ERR)
        {
                printf("can't install signal handler for SIGINT\n");
                exit(-1);
        }
        if (signal(SIGQUIT, sig_term) == SIG_ERR)
        {
                printf("can't install signal handler for SIGQUIT\n");
                exit(-1);
        }
        
	INIT_LOG("TMON");
	system("ln -s /tmp/test.html   /www/test.html");
	memset(&acc, 0, sizeof(acc));
	check_iptables();
	if (ipt_ACCOUNT_init(&ctx))
	{
		LOG("Init failed: %s\n", ctx.error_str);
		exit(-1);
	}
	
	pthread_mutex_init(&lock, NULL);
	pthread_create(&ubus_thread, NULL, ubus_loop, NULL);
	account_loop(NULL);
	return 0;
}