// Copyright 2013 Google Inc. All Rights Reserved.
//
// Clock - Platform independent interface for a time library
//
#ifndef CDM_BASE_CLOCK_H_
#define CDM_BASE_CLOCK_H_

#include <stdint.h>

namespace wvcdm {

// Provides time related information. The implementation is platform dependent.
class Clock {

 public:
  Clock() {}
  virtual ~Clock() {}

  // Provides the number of seconds since an epoch - 01/01/1970 00:00 UTC
  virtual int64_t GetCurrentTime();
};

};  // namespace wvcdm

#endif  // CDM_BASE_CLOCK_H_
