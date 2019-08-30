#
#  To be included by platform-specific vendor Android.mk to build
#  Widevine DRM plugin.  Sets up includes and defines the core libraries
#  required to build the plugin.
#
include $(TOP)/vendor/widevine/proprietary/drmwvmplugin/common.mk

ifndef BOARD_WIDEVINE_OEMCRYPTO_LEVEL
$(error BOARD_WIDEVINE_OEMCRYPTO_LEVEL not defined!)
endif

LOCAL_WHOLE_STATIC_LIBRARIES := \
    libdrmframeworkcommon \
    libdrmwvmcommon \
    libwvocs_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL)

LOCAL_SHARED_LIBRARIES := \
    libbinder \
    libutils \
    libcutils \
    liblog \
    libstlport \
    libz \
    libwvdrm_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL) \
    libWVStreamControlAPI_L$(BOARD_WIDEVINE_OEMCRYPTO_LEVEL) \
    libdl
