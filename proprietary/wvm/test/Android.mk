ifneq ($(filter arm x86,$(TARGET_ARCH)),)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
        Testlibwvm.cpp

LOCAL_C_INCLUDES+=                      \
    bionic                              \
    vendor/widevine/proprietary/include \
    external/stlport/stlport            \
    frameworks/av/media/libstagefright

ifeq ($(TARGET_ARCH),x86)
LOCAL_C_INCLUDES += $(TOP)/system/core/include/arch/linux-x86
endif

LOCAL_SHARED_LIBRARIES := \
    libstlport            \
    libdrmframework       \
    libstagefright        \
    liblog                \
    libutils              \
    libz                  \
    libdl

LOCAL_MODULE:=test-libwvm

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)

endif
