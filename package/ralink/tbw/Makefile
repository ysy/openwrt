#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tbw
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/tbw
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:= Bandwith control
  DEPENDS:= +libubox +libubus +libblobmsg-json +libpthread +tc +iptables-mod-iprange +iptables-mod-ipopt +iptables-mod-ipmark \
	 +kmod-sched-core +kmod-sched-connmark +kmod-ifb +iptables +iptables-mod-conntrack-extra +iptables-mod-u32
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

TARGET_LDFLAGS+=-lubox -ljson-c -lubus -lblobmsg_json -lpthread

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/tbw/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tbw $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tbw.init $(1)/etc/init.d/tbw
	
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/30-tbw  $(1)/etc/hotplug.d/iface/
endef

$(eval $(call BuildPackage,tbw))
