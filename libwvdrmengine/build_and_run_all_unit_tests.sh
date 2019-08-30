#!/bin/sh

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "Android build environment not set"
    exit -1
fi

. $ANDROID_BUILD_TOP/build/envsetup.sh

cd $ANDROID_BUILD_TOP/external/gtest/
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/test/gmock
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/cdm/test
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/mediacrypto/test
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/mediadrm/test
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/oemcrypto/test
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/test/unit
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine/test/java/src/com/widevine/test
pwd
mm

cd $ANDROID_BUILD_TOP/vendor/widevine/libwvdrmengine
./run_all_unit_tests.sh
