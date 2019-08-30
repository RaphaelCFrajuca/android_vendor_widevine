// Copyright 2013 Google Inc. All Rights Reserved.
//
// Timer class - provides a simple Android specific timer implementation

#include <unistd.h>

#include "timer.h"
#include "utils/RefBase.h"
#include "utils/StrongPointer.h"
#include "utils/Thread.h"

namespace wvcdm {

class Timer::Impl : virtual public android::RefBase {
 private:
  class ImplThread : public android::Thread {
   public:
    ImplThread() : Thread(false), handler_(NULL), period_(0) {}
    virtual ~ImplThread() {};

    bool Start(TimerHandler *handler, uint32_t time_in_secs) {
      handler_ = handler;
      period_ = time_in_secs;
      return run() == android::NO_ERROR;
    }

   private:
    virtual bool threadLoop() {
      struct timeval timeout;
      timeout.tv_sec = period_;
      timeout.tv_usec = 0;
      TEMP_FAILURE_RETRY(select(0, NULL, NULL, NULL, &timeout));
      handler_->OnTimerEvent();
      return true;
    }

    TimerHandler *handler_;
    uint32_t period_;

    CORE_DISALLOW_COPY_AND_ASSIGN(ImplThread);
  };

  android::sp<ImplThread> impl_thread_;

 public:
  Impl() {}
  virtual ~Impl() {};

  bool Start(TimerHandler *handler, uint32_t time_in_secs) {
    impl_thread_ = new ImplThread();
    return impl_thread_->Start(handler, time_in_secs);
  }

  void Stop() {
    impl_thread_->requestExitAndWait();
    impl_thread_.clear();
  }

  bool IsRunning() {
    return (impl_thread_ != NULL) && (impl_thread_->isRunning());
  }

  CORE_DISALLOW_COPY_AND_ASSIGN(Impl);
};

Timer::Timer() : impl_(new Timer::Impl()) {
}

Timer::~Timer() {
  if (IsRunning())
    Stop();

  delete impl_;
  impl_ = NULL;
}

bool Timer::Start(TimerHandler *handler, uint32_t time_in_secs) {
  if (!handler || time_in_secs == 0)
    return false;

  return impl_->Start(handler, time_in_secs);
}

void Timer::Stop() {
  impl_->Stop();
}

bool Timer::IsRunning() {
  return impl_->IsRunning();
}

} // namespace wvcdm
