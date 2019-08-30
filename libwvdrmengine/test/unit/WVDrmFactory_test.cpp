/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 */

#include "gtest/gtest.h"
#include "utils/UniquePtr.h"
#include "WVDrmFactory.h"

using namespace wvdrm;
using namespace android;

const uint8_t kWidevineUUID[16] = {
  0xED,0xEF,0x8B,0xA9,0x79,0xD6,0x4A,0xCE,
  0xA3,0xC8,0x27,0xDC,0xD5,0x1D,0x21,0xED
};

const uint8_t kOldNetflixWidevineUUID[16] = {
  0x29,0x70,0x1F,0xE4,0x3C,0xC7,0x4A,0x34,
  0x8C,0x5B,0xAE,0x90,0xC7,0x43,0x9A,0x47
};

const uint8_t kUnknownUUID[16] = {
  0x6A,0x7F,0xAA,0xB0,0x83,0xC7,0x9E,0x20,
  0x08,0xBC,0xEF,0x32,0x34,0x1A,0x9A,0x26
};

TEST(WVDrmFactoryTest, SupportsSupportedCryptoSchemes) {
  WVDrmFactory factory;

  EXPECT_TRUE(factory.isCryptoSchemeSupported(kWidevineUUID)) <<
      "WVPluginFactory does not support Widevine's UUID";

  EXPECT_TRUE(factory.isCryptoSchemeSupported(kOldNetflixWidevineUUID)) <<
      "WVPluginFactory does not support the old Netflix Widevine UUID";
}

TEST(WVDrmFactoryTest, DoesNotSupportUnsupportedCryptoSchemes) {
  WVDrmFactory factory;

  EXPECT_FALSE(factory.isCryptoSchemeSupported(kUnknownUUID)) <<
      "WVPluginFactory incorrectly claims to support an unknown UUID";
}

TEST(WVDrmFactoryTest, SupportsSupportedContainerFormats) {
  WVDrmFactory factory;

  EXPECT_TRUE(factory.isContentTypeSupported(String8("video/mp4"))) <<
      "WVPluginFactory does not support ISO-BMFF";
}

TEST(WVDrmFactoryTest, DoesNotSupportUnsupportedContainerFormats) {
  WVDrmFactory factory;

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/webm"))) <<
      "WVPluginFactory incorrectly claims to support Web-M";

  // Taken from Encoding.com's list of the most common internet video MIME-types
  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/x-matroska"))) <<
      "WVPluginFactory incorrectly claims to support Matroska";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/x-flv"))) <<
      "WVPluginFactory incorrectly claims to support Flash Video";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("application/x-mpegURL"))) <<
      "WVPluginFactory incorrectly claims to support m3u8 Indexes";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/MP2T"))) <<
      "WVPluginFactory incorrectly claims to support MPEG-2 TS";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/3gpp"))) <<
      "WVPluginFactory incorrectly claims to support 3GP Mobile";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/quicktime"))) <<
      "WVPluginFactory incorrectly claims to support Quicktime";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/x-msvideo"))) <<
      "WVPluginFactory incorrectly claims to support AVI";

  EXPECT_FALSE(factory.isContentTypeSupported(String8("video/x-ms-wmv"))) <<
      "WVPluginFactory incorrectly claims to support WMV";
}
