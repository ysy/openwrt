#!/bin/sh
. /lib/netifd/netifd-wireless.sh
. /lib/wifi/ralink_common.sh

init_wireless_driver "$@"

drv_mt7620_init_device_config() {
	config_add_string hwmode
	config_add_int beacon_int chanbw frag rts
	config_add_int rxantenna txantenna antenna_gain txpower distance
	config_add_boolean noscan ht_coex
	config_add_array ht_capab
	config_add_boolean \
		rxldpc \
		short_gi_80 \
		short_gi_160 \
		tx_stbc_2by1 \
		su_beamformer \
		su_beamformee \
		mu_beamformer \
		mu_beamformee \
		vht_txop_ps \
		htc_vht \
		rx_antenna_pattern \
		tx_antenna_pattern
	config_add_int vht_max_a_mpdu_len_exp vht_max_mpdu vht_link_adapt vht160 rx_stbc tx_stbc
	config_add_boolean \
		ldpc \
		greenfield \
		short_gi_20 \
		short_gi_40 \
		max_amsdu \
		dsss_cck_40
}

drv_mt7620_init_iface_config() {
	config_add_boolean wds powersave
	config_add_int maxassoc
	config_add_int max_listen_int
	config_add_int dtim_period
}

drv_mt7620_cleanup() {
	logger "cleanup"
}

drv_mt7620_setup() {
	echo  "setup" >> /tmp/wifi.log
	json_dump >>/tmp/wifi.log
	#sleep 2
	/sbin/wifi reload_legacy
	wireless_set_up
	#enable_ralink_wifi mt7620 mt7620
	#json_select config
	#json_get_vars \
		#phy macaddr path \
		#country chanbw distance \
		#txpower antenna_gain \
		#rxantenna txantenna \
		#frag rts beacon_int htmode
	#json_get_values basic_rate_list basic_rate
	#json_select ..

}

drv_mt7620_teardown() {
	echo  "teardown" >> /tmp/wifi.log
	json_dump >> /tmp/wifi.log
	/sbin/wifi reload_legacy
	#disable_ralink_wifi mt7620 mt7620
}

add_driver mt7620
