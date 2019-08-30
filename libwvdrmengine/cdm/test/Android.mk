# ----------------------------------------------------------------
# Builds CDM Tests
#
LOCAL_PATH := $(call my-dir)

test_name := base64_test
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := cdm_engine_test
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := device_files_unittest
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := file_store_unittest
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := http_socket_test
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := license_unittest
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := policy_engine_unittest
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name := request_license_test
test_src_dir := .
include $(LOCAL_PATH)/unit-test.mk

test_name := timer_unittest
test_src_dir := ../core/test
include $(LOCAL_PATH)/unit-test.mk

test_name :=
test_src_dir :=
