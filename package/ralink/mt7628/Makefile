# All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=mt7628-wifi
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk


define Package/mt7628-wifi
  CATEGORY:=MTK Properties
  TITLE:=MTK MT7628 wifi AP driver
  DEPENDS:=@TARGET_ramips_mt7628
  SUBMENU:=Drivers
  MENU:=1
endef

define Build/Prepare
	echo
endef

define Build/Compile
	echo
endef

define Package/mt7628-wifi/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/mt7628.sh $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/ralink_common.sh $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/etc/wireless/mt7628/
		
	$(INSTALL_DIR) $(1)/lib/netifd/wireless
	$(INSTALL_BIN) ./files/mt7628_netifd.sh $(1)/lib/netifd/wireless/mt7628.sh
	$(INSTALL_BIN) ./files/ralink-netifd.sh $(1)/lib/netifd/ralink-netifd.sh

	$(INSTALL_DIR) $(1)/lib/modules/$(LINUX_VERSION) $(1)/etc/Wireless/RT2860/
	$(INSTALL_DIR) $(1)/etc/modules.d/
	$(INSTALL_BIN) ./files/50-wifi  $(1)/etc/modules.d/	
	$(CP) modules/* $(1)/lib/modules/$(LINUX_VERSION)
endef

$(eval $(call BuildPackage,mt7628-wifi))
