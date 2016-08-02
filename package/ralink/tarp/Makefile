#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tarp
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/tarp
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  DEPENDS:=
  TITLE:=ARP static binding
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef


define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef


define Package/tarp/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/arp.init $(1)/etc/init.d/arp
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/arp.config $(1)/etc/config/arp
endef

$(eval $(call BuildPackage,tarp))
