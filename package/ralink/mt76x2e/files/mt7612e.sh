#!/bin/sh
append DRIVERS "mt7612e"

. /lib/wifi/ralink_common.sh

prepare_mt7612e() {
	prepare_ralink_wifi mt7612e
}

scan_mt7612e() {
	scan_ralink_wifi mt7612e mt76x2e
}

disable_mt7612e() {
	disable_ralink_wifi mt7612e
}

enable_mt7612e() {
	enable_ralink_wifi mt7612e mt76x2e
}

detect_mt7612e() {
#	detect_ralink_wifi mt7612e mt76x2e
	cd /sys/module/
	[ -d $module ] || return
	uci get wireless.mt7612e >/dev/null 2>&1 && return
	ifconfig rai0 >/dev/null 2>&1 || return
	cat <<EOF
config wifi-device mt7612e
#	option type mt7612e
#	option vendor ralink
#	option band 5G
#	option channel 0
#	option autoch 2
	option type 'mt7612e'
	option vendor 'ralink'
	option band '5G'
	option autoch '2'
	option radio '1'
	option wifimode '14'
	option channel '56'
	option bw '2'
	option country 'None'
	option aregion '7'
	option bgprotect '0'
	option beacon '100'
	option dtim '1'
	option fragthres '2346'
	option rtsthres '2347'
	option txpower '100'
	option txpreamble '0'
	option shortslot '1'
	option txburst '1'
	option pktaggre '1'
	option ieee80211h '0'
	option ht_opmode '0'
	option ht_gi '1'
	option ht_rdg '0'
	option ht_stbc '1'
	option ht_amsdu '0'
	option ht_autoba '1'
	option ht_badec '0'
	option ht_distkip '1'
	option ht_ldpc '0'
	option vht_stbc '1'
	option vht_sgi '1'
	option vht_bw_sig '0'
	option vht_ldpc '0'
	option ht_txstream '2'
	option ht_rxstream '2'


config wifi-iface
	option device mt7612e
	option ifname rai0
	option network lan
	option mode ap
	option ssid OpenWrt-5G
	option encryption none

EOF

}

