#!/bin/sh

ralink_sync_uci_with_dat() {
    echo "sync_uci_with_dat($1,$2,$3,$4)" >>/tmp/wifi.log
    local device="$1"
    ln -s  /tmp/"$device".dat /etc/wireless/$device/$device.dat
    uci2dat -d $device -f /tmp/$device.dat > /tmp/uci2dat.log
}

ralink_setup_interface() {                            
        local iface="$1"           
        local config="$2" 
                
        [ -n "$config" ] || return 0
	ubus call network.interface.lan add_device "{ \"name\": \"$iface\" }"
}


ralink_chk8021x() {
        local x8021x="0" encryption device="$1" prefix
	ifname="$1"
	encryption="$2"
        
        echo "enc = $encryption" >> /tmp/802.$device.log
        case "$encryption" in
		wpa+*)
			[ "$x8021x" == "0" ] && x8021x=1
			echo 111 >> /tmp/802.$device.log
		;;
		wpa2+*)
			[ "$x8021x" == "0" ] && x8021x=1
				echo 1l2 >> /tmp/802.$device.log
		;;
		wpa-mixed*)
			[ "$x8021x" == "0" ] && x8021x=1
		echo 1l3 >> /tmp/802.$device.log
		;;
	esac

	ifpre=$(echo $ifname | cut -c1-3)
	echo "prefix = $ifpre" >> /tmp/802.$device.log
	if [ "$ifpre" == "rai" ]; then
		prefix="rai"
	else
		prefix="ra"
	fi

        echo "x8021x $x8021x, pre $prefix" >>/tmp/802.$device.log
        if [ "1" == $x8021x ]; then
            if [ "$prefix" == "ra" ]; then
                echo "killall 8021xd" >>/tmp/802.$device.log
                killall 8021xd
                echo "/bin/8021xd -d 9" >>/tmp/802.$device.log
                /bin/8021xd -d 9 >> /tmp/802.$device.log 2>&1
            else # $prefixa == rai
                echo "killall 8021xdi" >>/tmp/802.$device.log
                killall 8021xdi
                echo "/bin/8021xdi -d 9" >>/tmp/802.$device.log
                /bin/8021xdi -d 9 >> /tmp/802.$device.log 2>&1
            fi
        else
            if [ "$prefix" == "ra" ]; then
                echo "killall 8021xd" >>/tmp/802.$device.log
                killall 8021xd
            else # $prefixa == rai
                echo "killall 8021xdi" >>/tmp/802.$device.log
                killall 8021xdi
            fi
        fi
}

ralink_init_device_config() {
	config_add_string type vendor band country txpower
	config_add_int channel autoch radio beacon dtim
}

ralink_init_iface_config() {
	config_add_string ifname
}

ralink_setup_vif() {
	json_select config
	json_get_vars ifname mode ssid encryption

	json_get_values network_list network
	echo "ifname: $ifname network: $network_list" >> /tmp/wifi.log
	echo "ifconfig $ifname down" >> /tmp/wifi.log
	ifconfig $ifname down
	sleep 1
	ifconfig $ifname up
	
	[ -z "$network_list" ] || {
		for network in $network_list ; do
			echo "setup_interface: $network" >>/tmp/wifi.log
			ralink_setup_interface $ifname $network
		done
	}
	
	ralink_chk8021x $ifname $encryption
}

ralink_teardown_vif() {
	json_select config
	json_get_vars ifname mode
	ifconfig $ifname down
	killall ap_client
}

ralink_setup() {
	echo  "drv_mt7620_setup" >> /tmp/wifi.log
	json_dump >>/tmp/wifi.log
	json_select config
	json_get_vars type
	json_select ..
	echo "type: $type" >>/tmp/wifi.log
	ralink_sync_uci_with_dat $type
	for_each_interface "ap sta adhoc mesh monitor" ralink_setup_vif
	wireless_set_up
}

ralink_teardown() {
	echo  "teardown" >> /tmp/wifi.log
	json_dump >> /tmp/wifi.log
	json_select config
	json_get_vars type
	json_select ..	
	for_each_interface "ap sta adhoc mesh monitor" ralink_teardown_vif	
}

