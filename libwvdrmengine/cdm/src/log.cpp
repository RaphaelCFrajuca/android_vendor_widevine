// Copyright 2013 Google Inc. All Rights Reserved.
//
// Log - implemented using the standard Android logging mechanism

/*
 * Qutoing from system/core/include/log/log.h:
 * Normally we strip ALOGV (VERBOSE messages) from release builds.
 * You can modify this (for example with "#define LOG_NDEBUG 0"
 * at the top of your source file) to change that behavior.
 */
#ifndef LOG_NDEBUG
#ifdef NDEBUG
#define LOG_NDEBUG 1
#else
#define LOG_NDEBUG 0
#endif
#endif

#define LOG_TAG "WVCdm"
#define LOG_BUF_SIZE 1024

#include "log.h"
#include "utils/Log.h"

namespace wvcdm {

void InitLogging(int argc, const char* const* argv) {}

void Log(const char* file, int line, LogPriority level, const char* fmt, ...) {
  va_list ap;
  char buf[LOG_BUF_SIZE];
  va_start(ap, fmt);
  vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
  va_end(ap);

  android_LogPriority prio = ANDROID_LOG_VERBOSE;

  switch(level) {
    case LOG_ERROR: prio = ANDROID_LOG_ERROR; break;
    case LOG_WARN: prio = ANDROID_LOG_WARN; break;
    case LOG_INFO: prio = ANDROID_LOG_INFO; break;
    case LOG_DEBUG: prio = ANDROID_LOG_DEBUG; break;
#if LOG_NDEBUG
    case LOG_VERBOSE: return;
#else
    case LOG_VERBOSE: prio = ANDROID_LOG_VERBOSE; break;
#endif
  }

  __android_log_write(prio, LOG_TAG, buf);
}

};  // namespace wvcdm
