ifneq ($(filter arm x86,$(TARGET_ARCH)),)

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
include $(TOP)/vendor/widevine/proprietary/wvm/common.mk

ifeq ($(BOARD_WIDEVINE_OEMCRYPTO_LEVEL),1)
LOCAL_CFLAGS := -DREQUIRE_SECURE_BUFFERS
endif

LOCAL_SRC_FILES:=           \
    WVMLogging.cpp          \
    WVMExtractorImpl.cpp    \
    WVMFileSource.cpp       \
    WVMMediaSource.cpp      \
    WVMInfoListener.cpp

LOCAL_SHARED_LIBRARIES := \
    libstagefright \
    libstagefright_foundation

LOCAL_MODULE := libwvmcommon
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)

endif
