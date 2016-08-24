#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <uci.h>

#include "log.h"

enum DEF_RULE  //Default rule for unmactch packages
{	
	DEF_PASS,
	DEF_DENY
};

#define PROTO_UDP     (1)
#define PROTO_TCP     (1<<1)

static struct uci_context *uci_ctx;
static struct uci_package *uci_filter;

static bool ip_enable = false;
static bool mac_enable = false;
static bool url_enable = false;
static enum DEF_RULE  ip_def;
static enum DEF_RULE  mac_def;
static enum DEF_RULE  url_def;

bool parse_boolean(struct uci_section * section, const char * name)
{
	const char *enable = uci_lookup_option_string(uci_ctx, section, name);
	
	if (enable && enable[0] == '1') 
		return true;
	else
		return false;   	
}

enum DEF_RULE parse_default_rule(struct uci_section * section, const char * name)
{
	const char *str = uci_lookup_option_string(uci_ctx, section, name);
	
	if (str && !strcmp(str, "pass")) 
		return DEF_PASS;
	else
		return DEF_DENY;
}

void time_to_utc(const char * local_time,  char * utc_time)
{
	struct tm tm;	
	memset(&tm, 0, sizeof(tm));
	
	tm.tm_year = 2016 - 1900;
	tm.tm_mon  = 1;
	tm.tm_mday = 1;
	tm.tm_hour = (local_time[0] - '0') * 10 + local_time[1] - '0';
	tm.tm_min =  (local_time[2] - '0') * 10 + local_time[3] - '0';
	time_t ti = mktime(&tm);
	//gmtime_r(&ti, &tm);
	sprintf(utc_time, "%02d:%02d", tm.tm_hour, tm.tm_min);
}

void parse_time(struct uci_section * section, char * start_time, char * stop_time)
{
	
	const char * time_str = uci_lookup_option_string(uci_ctx, section, "time");
	const char * tmp= strtok((char *)time_str, "-");
	
	time_to_utc(tmp, start_time);
	tmp= strtok(NULL, "-");
	time_to_utc(tmp, stop_time);
}


void handle_url_rule(struct uci_section * section)
{
	LOG("handle url rule");
	char cmd[1024];
	char hex_string[100];
	char buf[10];
	char start_time[10], stop_time[10];
	char *action;
	char * p;
	
	if (!url_enable || !parse_boolean(section, "enabled"))
		return;
	
	const char * url = uci_lookup_option_string(uci_ctx, section, "url");
	LOG("url=%s", url);
	parse_time(section, start_time, stop_time);
	
	if (url_def == DEF_DENY) 
		action = "RETURN";
	else
		action = "REJECT";
	
	sprintf(cmd, "iptables -t filter -A forwarding_rule -p tcp -m time --timestart %s --timestop %s --kerneltz "
							"-m string --string \"%s\" --algo bm -j %s", 
			 		start_time, stop_time, url, action);
	system(cmd);
	
	memset(hex_string, 0, sizeof(hex_string));
	p = strtok((char *)url, ".");
	while(p != NULL)
	{
		unsigned char len = (unsigned char)strlen(p);
		sprintf(buf, "|%02x|", len);
		strcat(hex_string, buf);
		strcat(hex_string, p);
		p = strtok(NULL, ".");
	}
	
	strcat(hex_string, "|00|");
	if (url_def == DEF_DENY) 
		action = "ACCEPT";
	else
		action = "DROP";
	
	sprintf(cmd, "iptables -t raw -A PREROUTING  -p udp --dport 53  -m time --timestart %s --timestop %s --kerneltz "
							"-m string --icase --hex-string \"%s\" --algo bm -j %s", 
			 		start_time, stop_time, hex_string, action);
	system(cmd);
}


void handle_mac_rule(struct uci_section * section)
{
	LOG("handle mac rule");
	char cmd[512];
	char *action;
	char start_time[10], stop_time[10];
	
	if (!mac_enable || !parse_boolean(section, "enabled"))
		return;
	
	if (mac_def == DEF_DENY) 
		action = "RETURN";
	else
		action = "REJECT";
	
	const char * mac = uci_lookup_option_string(uci_ctx, section, "mac");
	parse_time(section, start_time, stop_time);

	sprintf(cmd, "iptables -t filter -A mac_filter -m mac --mac-source %s -m time --timestart %s --timestop %s --kerneltz -j %s", 
			mac, start_time, stop_time, action);
	system(cmd);
}

void handle_ip_rule(struct uci_section * section)
{
	LOG("handle ip rule");
	char cmd[1024];
	char buf[100];
	char * p;
	unsigned char proto = 0;
	char start_time[10], stop_time[10];
	if (!ip_enable || !parse_boolean(section, "enabled"))
		return;
	
	const char *  src = uci_lookup_option_string(uci_ctx, section, "src");
	const char *  dst = uci_lookup_option_string(uci_ctx, section, "dst");
	const char *  dport = uci_lookup_option_string(uci_ctx, section, "dport");
	const char *  sport = uci_lookup_option_string(uci_ctx, section, "sport");
	const char *  proto_str = uci_lookup_option_string(uci_ctx, section, "proto");
	bool pass = parse_boolean(section, "pass");
	
	const char * action;
	if (pass)
		action = "RETURN";
	else
		action = "REJECT";
	
	if (!proto_str)
		proto = PROTO_TCP | PROTO_UDP;
	else if (!strcmp(proto_str, "all"))
		proto = PROTO_TCP | PROTO_UDP;
	else if (!strcmp(proto_str, "tcp"))
		proto = PROTO_TCP;
	else if (!strcmp(proto_str, "udp"))
		proto = PROTO_UDP;
	
	parse_time(section, start_time, stop_time);
	
	sprintf(cmd, "iptables -t filter -A ip_filter -p XXX ");
	
	if (dport)
	{
		p = strstr(dport, "-");
		if (p)
			*p = ':';
		sprintf(buf, "--dport %s ", dport);
		strcat(cmd, buf);
	} 
	
	if (sport)
	{
		p = strstr(sport, "-");
		if (p)
			*p = ':';
		
		sprintf(buf, "--sport %s ", dport);
		strcat(cmd, buf);
	}
	
	if (src || dst)
	{
		strcat(cmd, "-m iprange ");
		if (src)
		{
			sprintf(buf, "--src-range %s ", src);
			strcat(cmd, buf);
		}
		
		if (dst)
		{
			sprintf(buf, "--dst-range %s ", dst);
			strcat(cmd, buf);
		}
	}
	
	sprintf(buf, "-m time --timestart %s --timestop %s --kerneltz -j %s", 
			start_time, stop_time, action);
	
	strcat(cmd, buf);
	
	char * p_proto = strstr(cmd, "XXX");
	if (proto & PROTO_TCP)
	{
		memcpy(p_proto, "tcp", 3);
		system(cmd);
	}
	
	if (proto & PROTO_UDP)
	{
		memcpy(p_proto, "udp", 3);
		system(cmd);
	}	
}

void load_config()
{
	uci_ctx = uci_alloc_context();
	if (uci_load(uci_ctx, "filter", &uci_filter) )
	{
		LOG("config:failed to load config");
		exit(-1);
	}
	
	struct uci_section *globals = uci_lookup_section(
                        uci_ctx, uci_filter, "globals");
	if (!globals) 
	{
		LOG("config: globals section not found");
		return;
	}
	
	ip_enable = parse_boolean(globals, "ip_enable");
	mac_enable = parse_boolean(globals, "mac_enable");
	url_enable = parse_boolean(globals, "url_enable");
	ip_def = parse_default_rule(globals, "ip_default");
	mac_def = parse_default_rule(globals, "mac_default");
	url_def = parse_default_rule(globals, "url_default");
	
	struct uci_element *e;
	uci_foreach_element(&uci_filter->sections, e) 
	{
		struct uci_section *s = uci_to_section(e);
		if (!strcmp(s->type, "rule"))
		{
			const char *str = uci_lookup_option_string(uci_ctx, s, "type");
			if (str && !strcmp(str, "mac")) 
			{
				handle_mac_rule(s);
			} else if (str && !strcmp(str, "url")) 
			{
				handle_url_rule(s);
			} else if (str && !strcmp(str, "ip")) 
			{
				handle_ip_rule(s);
			}
		}
	}
	
	if (mac_enable)
	{
		if (mac_def == DEF_DENY)
			system("iptables -t filter -A mac_filter -j REJECT");
	}
	
	if (ip_enable)
	{
		if (ip_def == DEF_DENY)
			system("iptables -t filter -A ip_filter -j REJECT");
	}
	
	if (url_enable)
	{
		if (url_def == DEF_DENY)
		{
			system("iptables -t raw -A PREROUTING -p udp --dport 53 -j DROP");
			system("iptables -t filter -A url_filter -j REJECT");
		}
	}
}

void init_iptables()
{
	system("iptables -t filter -F forwarding_lan_rule");
	
	system("iptables -t filter -N mac_filter");
	system("iptables -t filter -N ip_filter");
	system("iptables -t filter -N url_filter");
	system("iptables -t filter -F mac_filter");
	system("iptables -t filter -F ip_filter");
	system("iptables -t filter -F url_filter");
	
	system("iptables -t filter -A forwarding_lan_rule -j mac_filter");
	system("iptables -t filter -A forwarding_lan_rule -j ip_filter");
	system("iptables -t filter -A forwarding_lan_rule -j url_filter");
	system("iptables -t raw -F PREROUTING");
	system("iptables -t filter -F forwarding_rule");
	
	system("date -k");	
	system("rmmod xt_time");
	system("insmod xt_time");
}


int main(int argc,  char * argv[])
{
	INIT_LOG("tfilter");
	good_checker();
	init_iptables();
	load_config();
	return 0;
}
