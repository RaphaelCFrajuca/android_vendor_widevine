LOCAL_C_INCLUDES:=                      \
    bionic                              \
    bionic/libstdc++                    \
    external/stlport/stlport            \
    frameworks/av/media/libstagefright/include \
    vendor/widevine/proprietary/streamcontrol/include \
    vendor/widevine/proprietary/wvm/include

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += $(TOP)/system/core/include/arch/linux-x86
endif
