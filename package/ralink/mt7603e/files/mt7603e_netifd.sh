#!/bin/sh
. /lib/netifd/netifd-wireless.sh
. /lib/netifd/ralink-netifd.sh

init_wireless_driver "$@"

drv_mt7603e_init_device_config() {
	ralink_init_device_config
}

drv_mt7603e_init_iface_config() {
	ralink_init_iface_config
}

drv_mt7603e_cleanup() {
	echo "cleanup" >> /tmp/wifi.log
}

drv_mt7603e_setup() {
	ralink_setup
}

drv_mt7603e_teardown() {
	ralink_teardown
}

add_driver mt7603e
