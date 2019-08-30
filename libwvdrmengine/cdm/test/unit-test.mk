# -------------------------------------------------------------------
# Makes a unit or end to end test.
# test_name must be passed in as the base filename(without the .cpp).
#
$(call assert-not-null,test_name)

include $(CLEAR_VARS)

LOCAL_MODULE := $(test_name)
LOCAL_MODULE_TAGS := tests

LOCAL_SRC_FILES := \
    $(test_src_dir)/$(test_name).cpp \
    ../core/test/config_test_env.cpp \
    ../core/test/http_socket.cpp \
    ../core/test/license_request.cpp \
    ../core/test/url_request.cpp

LOCAL_C_INCLUDES := \
    bionic \
    external/gtest/include \
    external/openssl/include \
    external/stlport/stlport \
    vendor/widevine/libwvdrmengine/android/cdm/test \
    vendor/widevine/libwvdrmengine/cdm/core/include \
    vendor/widevine/libwvdrmengine/cdm/core/test \
    vendor/widevine/libwvdrmengine/cdm/include \
    vendor/widevine/libwvdrmengine/oemcrypto/include \
    vendor/widevine/libwvdrmengine/test/gmock/include

LOCAL_C_INCLUDES += external/protobuf/src

LOCAL_ADDITIONAL_DEPENDENCIES := $(cdm_proto_gen_headers)

LOCAL_STATIC_LIBRARIES := \
    libcdm \
    libcdm_protos \
    libgmock \
    libgtest \
    libgtest_main \
    libwvlevel3 \
    libcdm_utils \
    libprotobuf-cpp-2.3.0-lite

LOCAL_SHARED_LIBRARIES := \
    libcrypto \
    libcutils \
    libdl \
    liblog \
    libssl \
    libstlport \
    libutils

include $(BUILD_EXECUTABLE)
