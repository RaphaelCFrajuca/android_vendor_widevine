# ----------------------------------------------------------------
# Builds libcdm.a
#
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    bionic \
    external/stlport/stlport \
    vendor/widevine/libwvdrmengine/cdm/core/include \
    vendor/widevine/libwvdrmengine/cdm/include \
    vendor/widevine/libwvdrmengine/oemcrypto/include \
    vendor/widevine/libwvdrmengine/third_party/stringencoders/src

LOCAL_C_INCLUDES += \
    external/openssl/include \
    external/protobuf/src

LOCAL_STATIC_LIBRARIES := libcdm_protos
LOCAL_ADDITIONAL_DEPENDENCIES := $(cdm_proto_gen_headers)

SRC_DIR := src
CORE_SRC_DIR := core/src
LOCAL_SRC_FILES := \
    $(CORE_SRC_DIR)/buffer_reader.cpp \
    $(CORE_SRC_DIR)/cdm_engine.cpp \
    $(CORE_SRC_DIR)/cdm_session.cpp \
    $(CORE_SRC_DIR)/certificate_provisioning.cpp \
    $(CORE_SRC_DIR)/crypto_session.cpp \
    $(CORE_SRC_DIR)/device_files.cpp \
    $(CORE_SRC_DIR)/license.cpp \
    $(CORE_SRC_DIR)/oemcrypto_adapter_dynamic.cpp \
    $(CORE_SRC_DIR)/policy_engine.cpp \
    $(CORE_SRC_DIR)/privacy_crypto.cpp \
    $(SRC_DIR)/wv_content_decryption_module.cpp

LOCAL_MODULE := libcdm
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
