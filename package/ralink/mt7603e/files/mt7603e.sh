#!/bin/sh
append DRIVERS "mt7603e"

. /lib/wifi/ralink_common.sh

prepare_mt7603e() {
	prepare_ralink_wifi mt7603e
}

scan_mt7603e() {
	scan_ralink_wifi mt7603e mt7603e
}

#disable_mt7603e() {
#	disable_ralink_wifi mt7603e
#}

#enable_mt7603e() {
#	enable_ralink_wifi mt7603e mt7603e
#}

detect_mt7603e() {
#	detect_ralink_wifi mt7603e mt7603e
	ssid=mt7603e-`ifconfig eth0 | grep HWaddr | cut -c 51- | sed 's/://g'`
	cd /sys/module/
	[ -d $module ] || return
        [ -e /etc/config/wireless ] && return
         cat <<EOF
config wifi-device 'mt7603e'
        option type 'mt7603e'
        option vendor 'ralink'
        option band '2.4G'
        option channel '1'
        option radio '1'
        option wifimode '9'
        option bw '1'
        option country 'None'
        option region '5'
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
        option ht_bsscoexist '0'
        option ht_extcha '1'
        option ht_opmode '0'
        option ht_gi '1'
        option ht_rdg '0'
        option ht_stbc '1'
        option ht_amsdu '0'
        option ht_autoba '1'
        option ht_badec '0'
        option ht_distkip '1'
        option ht_ldpc '0'
        option ht_txstream '2'
        option ht_rxstream '2'

config wifi-iface
	option device 'mt7603e'
        option ifname 'ra0'
        option network 'lan'
        option mode 'ap'
        option ssid $ssid
        option key '12345678'
        option wmm '1'
        option apsd '0'
	option encryption 'psk2+ccmp'
EOF


}


