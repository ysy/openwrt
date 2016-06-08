#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=phddns
PKG_RELEASE:=1
PKG_FIXUP:=autoreconf
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/phddns
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:= Oray DDNS
  DEPENDS:=

endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/phddns/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/phddns $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ddns.init $(1)/etc/init.d/ddns
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/ddns.config $(1)/etc/config/ddns	
endef

$(eval $(call BuildPackage,phddns))
