// Copyright 2013 Google Inc. All Rights Reserved.

#include "gtest/gtest.h"
#include "timer.h"

namespace wvcdm {

class TestTimerHandler : public TimerHandler {
 public:
  TestTimerHandler() : timer_events_(0) {};
  virtual ~TestTimerHandler() {};

  virtual void OnTimerEvent() {
    timer_events_++;
  }

  uint32_t timer_events() { return timer_events_; }
  void ResetTimerEvents() { timer_events_ = 0; }

 private:
  uint32_t timer_events_;
};

TEST(TimerTest, ParametersCheck) {
  Timer timer;
  EXPECT_FALSE(timer.Start(NULL, 10));

  TestTimerHandler handler;
  EXPECT_FALSE(timer.Start(&handler, 0));
}

TEST(TimerTest, TimerCheck) {
  TestTimerHandler handler;
  Timer timer;
  uint32_t duration = 10;

  EXPECT_EQ(0u, handler.timer_events());
  EXPECT_FALSE(timer.IsRunning());

  EXPECT_TRUE(timer.Start(&handler, 1));
  EXPECT_TRUE(timer.IsRunning());
  sleep(duration);

  EXPECT_LE(duration-1, handler.timer_events());
  EXPECT_LE(handler.timer_events(), duration+1);
  timer.Stop();
  EXPECT_FALSE(timer.IsRunning());
  sleep(duration);

  EXPECT_LE(duration-1, handler.timer_events());
  EXPECT_LE(handler.timer_events(), duration+1);
}

}
