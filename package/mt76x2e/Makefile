#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mt76x2e

PKG_REV:=2714
PKG_VERSION:=r$(PKG_REV)
PKG_RELEASE:=6

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

PKG_KCONFIG:=  RLT_AP_SUPPORT \
 		WDS_SUPPORT \
 MBSS_SUPPORT \
 SNIFFER_SUPPORT \
 CFG80211_SUPPORT \
 NEW_MBSSID_MODE \
 ENHANCE_NEW_MBSSID_MODE \
 APCLI_SUPPORT \
 APCLI_CERT_SUPPORT \
 MAC_REPEATER_SUPPORT \
 DFS_SUPPORT \
 LLTD_SUPPORT \
 NINTENDO_AP \
 COC_SUPPORT \
 DELAYED_TCP_ACK_SUPPORT \
 BAND_STEERING \
 MCAST_RATE_SPECIFIC \
 THERMAL_PROTECT_SUPPORT \
 CON_WPS_SUPPORT  \
 SUPPORT_OPENWRT \
 RALINK_MT7612E  \
 DOT11N_DRAFT3 \
 ATE_SUPPORT \
 RLT_MAC  \
 DOT11_VHT_AC \
 NEW_RATE_ADAPT_SUPPORT \
 RTMP_FLASH_SUPPORT \
 RT2860V2_AP_MEMORY_OPTIMIZATION
 




define KernelPackage/mt76x2e
  CATEGORY:=MT76X2E
  TITLE:=Driver for MT76X2E
  DEPENDS:= +wireless-tools +maccalc
  FILES:=$(PKG_BUILD_DIR)/build/mt76x2e.ko
  AUTOLOAD:=$(call AutoLoad,50,mt76x2e)
endef

define KernelPackage/mt76x2e/description
 This package contains a driver for MT76X2E
endef

define KernelPackage/mt76x2e/config
	source "$(SOURCE)/config.in"
endef

SOURCE_DIR:=$(PKG_BUILD_DIR)
export SOURCE_DIR

MAKEOPTS:= -C $(LINUX_DIR) \
                ARCH="$(LINUX_KARCH)" \
                CROSS_COMPILE="$(TARGET_CROSS)" \
                M="$(PKG_BUILD_DIR)/build" \
                CONFIG_RLT_AP_SUPPORT=m \
		$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)=y)) \
		modules

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) -r files/. $(PKG_BUILD_DIR)
endef


define Build/Compile
	$(MAKE) $(MAKEOPTS)
endef

define KernelPackage/mt76x2e/install
	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_DATA) ./files/mt76x2e.sh $(1)/lib/wifi
endef

$(eval $(call KernelPackage,mt76x2e))
