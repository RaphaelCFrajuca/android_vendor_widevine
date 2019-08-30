// Copyright 2012 Google Inc. All Rights Reserved.
//
// Lock class - provides a simple android specific mutex implementation

#include "lock.h"
#include "utils/Mutex.h"

namespace wvcdm {

class Lock::Impl {
 public:
  android::Mutex lock_;
};

Lock::Lock() : impl_(new Lock::Impl()) {
}

Lock::~Lock() {
  delete impl_;
}

void Lock::Acquire() {
  impl_->lock_.lock();
}

void Lock::Release() {
  impl_->lock_.unlock();
}

bool Lock::Try() {
  return (impl_->lock_.tryLock() == 0);
}

};  // namespace wvcdm


