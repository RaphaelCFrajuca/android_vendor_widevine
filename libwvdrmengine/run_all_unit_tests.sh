#!/bin/sh

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "Android build environment not set"
    exit -1
fi

echo "waiting for device"
adb root && adb wait-for-device remount && adb sync

adb shell /system/bin/oemcrypto_test
adb shell /system/bin/request_license_test
adb shell /system/bin/request_license_test -icp --gtest_filter=WvCdmRequestLicenseTest.DISABLED_PrivacyModeTest --gtest_also_run_disabled_tests
adb shell /system/bin/request_license_test -icp --gtest_filter=WvCdmRequestLicenseTest.DISABLED_PrivacyModeWithServiceCertificateTest --gtest_also_run_disabled_tests
adb shell /system/bin/policy_engine_unittest
adb shell /system/bin/libwvdrmmediacrypto_test
adb shell /system/bin/libwvdrmdrmplugin_test
adb shell /system/bin/cdm_engine_test
adb shell /system/bin/file_store_unittest
adb shell /system/bin/device_files_unittest
adb shell /system/bin/timer_unittest
adb shell LD_LIBRARY_PATH=/system/vendor/lib/mediadrm/ /system/bin/libwvdrmengine_test

adb shell am start com.widevine.test/com.widevine.test.MediaDrmAPITest
# TODO: make this test more command line friendly
echo "check logcat output for MediaDrmAPITest"

