LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  WVCreatePluginFactories_test.cpp \
  WVCryptoFactory_test.cpp \
  WVDrmFactory_test.cpp \

LOCAL_C_INCLUDES := \
  bionic \
  external/gtest/include \
  external/stlport/stlport \
  frameworks/av/include \
  frameworks/native/include \
  vendor/widevine/libwvdrmengine/include \
  vendor/widevine/libwvdrmengine/mediadrm/include \
  vendor/widevine/libwvdrmengine/oemcrypto/include \

LOCAL_STATIC_LIBRARIES := \
  libgtest \
  libgtest_main \

LOCAL_SHARED_LIBRARIES := \
  libcrypto \
  libdl \
  liblog \
  libstlport \
  libutils \
  libwvdrmengine \

LOCAL_MODULE := libwvdrmengine_test

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
