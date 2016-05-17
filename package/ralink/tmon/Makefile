#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tmon
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/tmon
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:= ip traffic monitor
  DEPENDS:= +libubox +libubus +libblobmsg-json +iptaccount +libpthread
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

TARGET_LDFLAGS+=-lubox -ljson-c -lubus -lblobmsg_json -lxt_ACCOUNT_cl -lpthread

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/tmon/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tmon $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tmon.init $(1)/etc/init.d/tmon
endef

$(eval $(call BuildPackage,tmon))
