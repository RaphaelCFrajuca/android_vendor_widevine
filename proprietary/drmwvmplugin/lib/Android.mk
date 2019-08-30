ifneq ($(filter arm x86,$(TARGET_ARCH)),)

include $(call all-subdir-makefiles)

endif
