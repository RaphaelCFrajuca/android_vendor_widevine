# Copyright 2013 Google Inc. All Rights Reserved.

# gMock builds 2 libraries: libgmock and libgmock_main. libgmock
# contains most of the code and libgmock_main just
# provide a common main to run the test. (i.e. If you link against
# libgmock_main you shouldn't provide a main() entry point.)
#
# We build these 2 libraries for the target device and for the host if
# it is running linux and using ASTL.

LOCAL_PATH := $(call my-dir)

libgmock_target_includes := \
  $(LOCAL_PATH)/.. \
  $(LOCAL_PATH)/../include \
  external/gtest/include \

libgmock_host_includes := \
  $(LOCAL_PATH)/.. \
  $(LOCAL_PATH)/../include \
  external/gtest/include \

#######################################################################
# gmock lib host

include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := gmock-all.cc

LOCAL_C_INCLUDES := $(libgmock_host_includes)

LOCAL_CFLAGS += -O0

LOCAL_MODULE := libgmock_host

include $(BUILD_HOST_STATIC_LIBRARY)

#######################################################################
# gmock_main lib host

include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := gmock_main.cc

LOCAL_C_INCLUDES := $(libgmock_host_includes)

LOCAL_CFLAGS += -O0

LOCAL_MODULE := libgmock_main_host

include $(BUILD_HOST_STATIC_LIBRARY)

#######################################################################
# gmock lib target

include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH), arm)
   LOCAL_SDK_VERSION := 8
else
# NDK support of other archs (ie. x86 and mips) are only available after android-9
   LOCAL_SDK_VERSION := 9
endif

LOCAL_NDK_STL_VARIANT := stlport_static

LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := gmock-all.cc

LOCAL_C_INCLUDES := $(libgmock_target_includes)

LOCAL_MODULE := libgmock

include $(BUILD_STATIC_LIBRARY)

#######################################################################
# gmock_main lib target

include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH), arm)
   LOCAL_SDK_VERSION := 8
else
# NDK support of other archs (ie. x86 and mips) are only available after android-9
   LOCAL_SDK_VERSION := 9
endif

LOCAL_NDK_STL_VARIANT := stlport_static

LOCAL_CPP_EXTENSION := .cc

LOCAL_SRC_FILES := gmock_main.cc

LOCAL_C_INCLUDES := $(libgmock_target_includes)

LOCAL_MODULE := libgmock_main

include $(BUILD_STATIC_LIBRARY)
