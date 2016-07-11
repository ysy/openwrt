#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mt7620

PKG_REV:=2714
PKG_VERSION:=r$(PKG_REV)
PKG_RELEASE:=6

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

PKG_KCONFIG:=RT2860V2_AP_V24_DATA_STRUCTURE RT2860V2_AP_LED RT2860V2_AP_WSC RT2860V2_AP_WSC_V2 RT2860V2_AP_LLTD RT2860V2_AP_WDS RT2860V2_AP_WMM_ACM RT2860V2_AP_MBSS RT2860V2_AP_APCLI RT2860V2_AP_MAC_REPEATER RT2860V2_AP_IGMP_SNOOP RT2860V2_AP_NETIF_BLOCK RT2860V2_AP_DFS RT2860V2_AP_CARRIER RT2860V2_AP_DLS RT2860V2_AP_IDS RT2860V2_HW_ANTENNA_DIVERSITY RT2860V2_AP_WAPI RT2860V2_AP_COC RT2860V2_AP_MEMORY_OPTIMIZATION RT2860V2_AP_VIDEO_TURBINE RT2860V2_AP_INTELLIGENT_RATE_ADAPTION RT2860V2_AP_TXBF RT2860V2_EXT_CHANNEL_LIST RT2860V2_KTHREAD RT2860V2_AUTO_CH_SELECT_ENHANCE RT2860V2_AP_80211N_DRAFT3 RT2860V2_AP_RTMP_INTERNAL_TX_ALC RT2860V2_ADJ_PWR_CONSUMPTION_SUPPORT RT2860V2_SINGLE_SKU RT2860V2_AP_RTMP_INTERNAL_TX_ALC RT2860V2_AP_RTMP_TEMPERATURE_COMPENSATION RT2860V2_80211R_FT RT2860V2_80211R_RR RT2860V2_MCAST_RATE_SPECIFIC RT2860V2_SNMP RA_CLASSIFIER EXTERNAL_PA_EXTERNAL_LNA 


define KernelPackage/mt7620
  CATEGORY:=MTK Properties
  TITLE:=Driver for MT7620
  DEPENDS:=@TARGET_ramips +wireless-tools +maccalc
  DEFAULT:=y if (CONFIG_TARGET_ramips_mt7620n || CONFIG_TARGET_ramips_mt7620a)
  FILES:=$(PKG_BUILD_DIR)/rt2860v2_ap/mt7620.ko
  AUTOLOAD:=$(call AutoLoad,90,mt7620.ko)
  SUBMENU:=Drivers
  MENU:=1
endef

define KernelPackage/mt7620/description
 This package contains a driver for MT7620
endef

define KernelPackage/mt7620/config
	source "$(SOURCE)/config.in"
endef

SOURCE_DIR:=$(PKG_BUILD_DIR)
export SOURCE_DIR

MAKEOPTS:= -C $(LINUX_DIR) \
                ARCH="$(LINUX_KARCH)" \
                CROSS_COMPILE="$(TARGET_CROSS)" \
                M="$(PKG_BUILD_DIR)/rt2860v2_ap" \
                CONFIG_RT2860V2_AP=m \
		$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)=y)) \
		modules

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) -r files/. $(PKG_BUILD_DIR)
endef


define Build/Compile
	$(MAKE) $(MAKEOPTS)
endef

define KernelPackage/mt7620/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/mt7620.sh $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/lib/netifd/wireless
	$(INSTALL_BIN) ./files/mt7620_netifd.sh $(1)/lib/netifd/wireless/mt7620.sh
	$(INSTALL_BIN) ./files/ralink-netifd.sh $(1)/lib/netifd/ralink-netifd.sh
	
	$(INSTALL_DIR) $(1)/etc/wireless/mt7620/
	$(INSTALL_BIN) ./files/SingleSKU.dat $(1)/etc/wireless/mt7620/
	-if [ "$$(CONFIG_INTERNAL_PA_INTERNAL_LNA)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7620.eeprom.ipa.ilna.bin $(1)/etc/wireless/mt7620/mt7620.eeprom.bin; \
	elif [ "$$(CONFIG_INTERNAL_PA_EXTERNAL_LNA)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7620.eeprom.ipa.elna.bin $(1)/etc/wireless/mt7620/mt7620.eeprom.bin; \
	elif [ "$$(CONFIG_EXTERNAL_PA_EXTERNAL_LNA)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7620.eeprom.epa.elna.bin $(1)/etc/wireless/mt7620/mt7620.eeprom.bin; \
	else \
		$(INSTALL_BIN) ./files/mt7620.eeprom.ipa.elna.bin $(1)/etc/wireless/mt7620/mt7620.eeprom.bin; \
	fi
	echo p$(P4REV) > $(1)/etc/wireless/mt7620/version
endef

$(eval $(call KernelPackage,mt7620))
