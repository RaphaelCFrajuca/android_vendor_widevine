ifneq ($(filter arm x86,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    TestPlayer.cpp

LOCAL_MODULE_TAGS := tests

LOCAL_C_INCLUDES += \
    bionic \
    vendor/widevine/proprietary/include \
    external/stlport/stlport \
    vendor/widevine/proprietary/streamcontrol/include \
    vendor/widevine/proprietary/drmwvmplugin/include \
    frameworks/av/drm/libdrmframework/include \
    frameworks/av/drm/libdrmframework/plugins/common/include

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += $(TOP)/system/core/include/arch/linux-x86
endif

LOCAL_SHARED_LIBRARIES := \
    libstlport \
    libdrmframework \
    liblog \
    libutils \
    libz \
    libcutils \
    libdl \
    libWVStreamControlAPI_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL) \
    libwvdrm_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL)

LOCAL_MODULE:=test-wvplayer_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL)

include $(BUILD_EXECUTABLE)

endif
