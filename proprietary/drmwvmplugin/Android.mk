LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

########################
# Feature file for clients to look up widevine drm plug-in

include $(CLEAR_VARS)
LOCAL_MODULE := com.google.widevine.software.drm.xml
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_OWNER := widevine
LOCAL_MODULE_CLASS := ETC

# This will install the file in /system/etc/permissions
#
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/permissions

include $(BUILD_PREBUILT)

########################
# Dummy library used to indicate availability of widevine drm

include $(CLEAR_VARS)
LOCAL_MODULE := com.google.widevine.software.drm
LOCAL_SRC_FILES := src/StubLib.java
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_OWNER := widevine
LOCAL_MODULE_CLASS := JAVA_LIBRARIES

include $(BUILD_JAVA_LIBRARY)

########################

ifneq ($(filter arm x86,$(TARGET_ARCH)),)

include $(CLEAR_VARS)
include $(TOP)/vendor/widevine/proprietary/drmwvmplugin/common.mk

LOCAL_SRC_FILES:= \
    src/WVMDrmPlugin.cpp \
    src/WVMLogging.cpp

LOCAL_MODULE := libdrmwvmcommon
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)

# invoke Android.mk files in subdirs
include $(call all-makefiles-under,$(LOCAL_PATH))

endif
