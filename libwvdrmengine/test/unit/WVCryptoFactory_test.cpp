/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 */

#include "gtest/gtest.h"
#include "utils/UniquePtr.h"
#include "WVCryptoFactory.h"

using namespace wvdrm;

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

TEST(WVCryptoFactoryTest, SupportsSupportedCryptoSchemes) {
  UniquePtr<WVCryptoFactory> factory(new WVCryptoFactory());

  EXPECT_TRUE(factory->isCryptoSchemeSupported(kWidevineUUID)) <<
      "WVPluginFactory does not support Widevine's UUID";

  EXPECT_TRUE(factory->isCryptoSchemeSupported(kOldNetflixWidevineUUID)) <<
      "WVPluginFactory does not support the old Netflix Widevine UUID";
}

TEST(WVCryptoFactoryTest, DoesNotSupportUnsupportedCryptoSchemes) {
  UniquePtr<WVCryptoFactory> factory(new WVCryptoFactory());

  EXPECT_FALSE(factory->isCryptoSchemeSupported(kUnknownUUID)) <<
      "WVPluginFactory incorrectly claims to support an unknown UUID";
}
