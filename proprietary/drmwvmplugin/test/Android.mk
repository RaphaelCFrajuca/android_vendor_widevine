ifneq ($(filter arm x86,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    TestPlugin.cpp \
    ../src/WVMLogging.cpp

LOCAL_C_INCLUDES+= \
    bionic \
    vendor/widevine/proprietary/include \
    vendor/widevine/proprietary/drmwvmplugin/include \
    vendor/widevine/proprietary/streamcontrol/include \
    external/stlport/stlport \
    frameworks/av/drm/libdrmframework/include \
    frameworks/av/drm/libdrmframework/plugins/common/include

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += $(TOP)/system/core/include/arch/linux-x86
endif

LOCAL_SHARED_LIBRARIES := \
    libstlport            \
    liblog                \
    libutils              \
    libz                  \
    libdl

LOCAL_STATIC_LIBRARIES := \
    libdrmframeworkcommon

LOCAL_MODULE:=test-wvdrmplugin

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)

endif
