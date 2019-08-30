LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  src/WVDrmPlugin.cpp \

LOCAL_C_INCLUDES := \
  bionic \
  external/stlport/stlport \
  frameworks/av/include \
  frameworks/native/include \
  vendor/widevine/libwvdrmengine/cdm/core/include \
  vendor/widevine/libwvdrmengine/cdm/include \
  vendor/widevine/libwvdrmengine/include \
  vendor/widevine/libwvdrmengine/mediadrm/include \
  vendor/widevine/libwvdrmengine/oemcrypto/include \

LOCAL_MODULE := libwvdrmdrmplugin

LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
