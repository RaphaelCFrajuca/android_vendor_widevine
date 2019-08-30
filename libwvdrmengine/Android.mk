# -----------------------------------------------------------------------------
# CDM top level makefile
#
LOCAL_PATH := $(call my-dir)

# -----------------------------------------------------------------------------
# Builds libcdm_utils.a
#
include $(CLEAR_VARS)

LOCAL_MODULE := libcdm_utils
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_C_INCLUDES := \
    bionic \
    external/stlport/stlport \
    vendor/widevine/libwvdrmengine/cdm/core/include \
    vendor/widevine/libwvdrmengine/cdm/include \
    vendor/widevine/libwvdrmengine/oemcrypto/include \
    vendor/widevine/libwvdrmengine/third_party/stringencoders/src

SRC_DIR := cdm/src
CORE_SRC_DIR := cdm/core/src
LOCAL_SRC_FILES := third_party/stringencoders/src/modp_b64w.cpp \
    $(CORE_SRC_DIR)/properties.cpp \
    $(CORE_SRC_DIR)/string_conversions.cpp \
    $(SRC_DIR)/clock.cpp \
    $(SRC_DIR)/file_store.cpp \
    $(SRC_DIR)/lock.cpp \
    $(SRC_DIR)/log.cpp \
    $(SRC_DIR)/properties_android.cpp \
    $(SRC_DIR)/timer.cpp \

include $(BUILD_STATIC_LIBRARY)

# -----------------------------------------------------------------------------
# Builds libcdm_protos.a
# Generates *.a, *.pb.h and *.pb.cc for *.proto files.
#
include $(CLEAR_VARS)

LOCAL_MODULE := libcdm_protos
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_C_INCLUDES := \
    bionic \
    external/stlport/stlport

LOCAL_SRC_FILES := $(call all-proto-files-under, cdm/core/src)

# $(call local-intermediates-dir)/proto/$(LOCAL_PATH)/cdm/core/src is used
# to locate *.pb.h by cdm source
# $(call local-intermediates-dir)/proto is used to locate *.pb.h included
# by *.pb.cc
# The module that depends on this prebuilt will have LOCAL_C_INCLUDES prepended
# with this path.
LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(call local-intermediates-dir)/proto \
    $(call local-intermediates-dir)/proto/$(LOCAL_PATH)/cdm/core/src

include $(BUILD_STATIC_LIBRARY)

# proto_generated_headers is a build system internal variable defined in
# $(BUILD_STATIC_LIBRARY). We can use cdm_proto_gen_headers later to establish
# the dependency.
cdm_proto_gen_headers := $(proto_generated_headers)

# -----------------------------------------------------------------------------
# Builds libwvdrmengine.so
#
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  src/WVCDMSingleton.cpp \
  src/WVCreatePluginFactories.cpp \
  src/WVCryptoFactory.cpp \
  src/WVDrmFactory.cpp \
  src/WVUUID.cpp

LOCAL_C_INCLUDES := \
  bionic \
  external/stlport/stlport \
  frameworks/av/include \
  frameworks/native/include \
  vendor/widevine/libwvdrmengine/cdm/core/include \
  vendor/widevine/libwvdrmengine/cdm/include \
  vendor/widevine/libwvdrmengine/include \
  vendor/widevine/libwvdrmengine/mediacrypto/include \
  vendor/widevine/libwvdrmengine/mediadrm/include \
  vendor/widevine/libwvdrmengine/oemcrypto/include \

LOCAL_STATIC_LIBRARIES := \
  libcdm \
  libcdm_utils \
  libwvlevel3 \
  libprotobuf-cpp-2.3.0-lite \
  libwvdrmcryptoplugin \
  libwvdrmdrmplugin \

LOCAL_SHARED_LIBRARIES := \
  libcrypto \
  libcutils \
  libdl \
  liblog \
  libstlport \
  libutils \
  libstagefright_foundation \

LOCAL_WHOLE_STATIC_LIBRARIES := libcdm_protos

LOCAL_ADDITIONAL_DEPENDENCIES := $(cdm_proto_gen_headers)

LOCAL_MODULE := libwvdrmengine

LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)/mediadrm

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE_OWNER := widevine

include $(BUILD_SHARED_LIBRARY)

include vendor/widevine/libwvdrmengine/cdm/Android.mk
include vendor/widevine/libwvdrmengine/level3/Android.mk
include vendor/widevine/libwvdrmengine/mediacrypto/Android.mk
include vendor/widevine/libwvdrmengine/mediadrm/Android.mk

# clean up temp vars
cdm_proto_gen_headers :=
