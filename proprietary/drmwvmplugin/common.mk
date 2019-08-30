LOCAL_C_INCLUDES:= \
    $(TOP)/bionic \
    $(TOP)/bionic/libstdc++/include \
    $(TOP)/external/stlport/stlport \
    $(TOP)/vendor/widevine/proprietary/streamcontrol/include \
    $(TOP)/vendor/widevine/proprietary/drmwvmplugin/include \
    $(TOP)/frameworks/av/drm/libdrmframework/include \
    $(TOP)/frameworks/av/drm/libdrmframework/plugins/common/include \
    $(TOP)/frameworks/av/include

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += $(TOP)/system/core/include/arch/linux-x86
endif
