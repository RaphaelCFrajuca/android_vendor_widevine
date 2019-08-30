# widevine prebuilts only available for ARM
# To build this dir you must define BOARD_WIDEVINE_OEMCRYPTO_LEVEL in the board config.
ifdef BOARD_WIDEVINE_OEMCRYPTO_LEVEL
ifeq ($(TARGET_ARCH),arm)

include $(call all-subdir-makefiles)

endif # TARGET_ARCH == arm, x86
endif # BOARD_WIDEVINE_OEMCRYPTO_LEVEL
