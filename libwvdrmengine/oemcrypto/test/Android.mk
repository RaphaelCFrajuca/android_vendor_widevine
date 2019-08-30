LOCAL_PATH:= $(call my-dir)

# THIS IS FOR THE MOCK TESTS:
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
  oemcrypto_test.cpp

LOCAL_MODULE_TAGS := tests

LOCAL_C_INCLUDES += \
  bionic \
  external/gtest/include \
  external/openssl/include \
  external/stlport/stlport \
  $(LOCAL_PATH)/../include \
  $(LOCAL_PATH)/../mock/src \
  vendor/widevine/libwvdrmengine/cdm/core/include \
  vendor/widevine/libwvdrmengine/third_party/stringencoders/src \

LOCAL_STATIC_LIBRARIES := \
  libcdm \
  libgtest \
  libgtest_main \
  libwvlevel3 \
  libcdm_utils \

LOCAL_SHARED_LIBRARIES := \
  libcrypto \
  libcutils \
  libdl \
  liblog \
  libstlport \
  libutils \
  libz \

LOCAL_MODULE:=oemcrypto_test

include $(BUILD_EXECUTABLE)
