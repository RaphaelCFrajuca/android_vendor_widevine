//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#include "gtest/gtest.h"
#include "utils/UniquePtr.h"
#include "WVCreatePluginFactories.h"

using namespace android;

TEST(CreatePluginFactoriesTest, CreatesDrmFactory) {
  UniquePtr<DrmFactory> factory(createDrmFactory());

  EXPECT_NE((DrmFactory*)NULL, factory.get()) <<
      "createDrmFactory() returned null";
}

TEST(CreatePluginFactoriesTest, CreatesCryptoFactory) {
  UniquePtr<CryptoFactory> factory(createCryptoFactory());

  EXPECT_NE((CryptoFactory*)NULL, factory.get()) <<
      "createCryptoFactory() returned null";
}
