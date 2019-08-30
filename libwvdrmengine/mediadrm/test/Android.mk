LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  WVDrmPlugin_test.cpp \

LOCAL_C_INCLUDES := \
  bionic \
  external/gtest/include \
  external/stlport/stlport \
  frameworks/av/include \
  frameworks/native/include \
  vendor/widevine/libwvdrmengine/cdm/core/include \
  vendor/widevine/libwvdrmengine/cdm/include \
  vendor/widevine/libwvdrmengine/mediadrm/include \
  vendor/widevine/libwvdrmengine/oemcrypto/include \
  vendor/widevine/libwvdrmengine/test/gmock/include \

LOCAL_STATIC_LIBRARIES := \
  libcdm \
  libcdm_protos \
  libcdm_utils \
  libgmock \
  libgmock_main \
  libgtest \
  libwvlevel3 \
  libprotobuf-cpp-2.3.0-lite \
  libwvdrmdrmplugin \

LOCAL_SHARED_LIBRARIES := \
  libcrypto \
  libcutils \
  libdl \
  liblog \
  libstlport \
  libutils \

# CDM's protobuffers are not part of the library
PROTO_SRC_DIR := $(proto_generated_cc_sources_dir)/$(LOCAL_PATH)/core/src

LOCAL_SRC_FILES += \
  $(PROTO_SRC_DIR)/license_protocol.pb.cc \

LOCAL_C_INCLUDES += \
  $(proto_generated_cc_sources_dir)/$(LOCAL_PATH)/core/src \
  external/protobuf/src \

LOCAL_ADDITIONAL_DEPENDENCIES += $(proto_generated_headers)

# End protobuf section

LOCAL_MODULE := libwvdrmdrmplugin_test

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
