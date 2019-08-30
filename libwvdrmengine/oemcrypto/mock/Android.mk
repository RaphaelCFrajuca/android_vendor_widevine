LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    src/oemcrypto_engine_mock.cpp \
    src/oemcrypto_key_mock.cpp \
    src/oemcrypto_keybox_mock.cpp \
    src/oemcrypto_mock.cpp \
    src/wvcrc.cpp \

LOCAL_MODULE_TAGS := tests

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../include \
    $(LOCAL_PATH)/src \
    vendor/widevine/libwvdrmengine/cdm/core/include \
    vendor/widevine/libwvdrmengine/third_party/stringencoders/src \
    bionic \
    external/gtest/include \
    external/openssl/include \
    external/openssl/include/openssl \
    external/stlport/stlport \

LOCAL_SHARED_LIBRARIES := \
    libcrypto \
    libcutils \
    libdl \
    liblog \
    libstlport \
    libutils \
    libz \

LOCAL_STATIC_LIBRARIES := \
    libcdm_utils

LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)
LOCAL_MODULE := liboemcrypto

include $(BUILD_SHARED_LIBRARY)

