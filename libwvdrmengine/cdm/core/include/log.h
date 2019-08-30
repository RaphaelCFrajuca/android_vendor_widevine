// Copyright 2013 Google Inc. All Rights Reserved.
//
// Log - Platform independent interface for a Logging class
//
#ifndef CDM_BASE_LOG_H_
#define CDM_BASE_LOG_H_

namespace wvcdm {

// Simple logging class. The implementation is platform dependent.

typedef enum {
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG,
  LOG_VERBOSE
} LogPriority;

// Required to enable/disable verbose logging (LOGV) in Chromium. In Chromium,
// verbose logging level is controlled using command line switches --v (global)
// or --vmodule (per module). This function calls logging::InitLogging to
// initialize logging, which should have already been included in most Chromium
// based binaries. However, it is typically not included by default in
// unittests, in particular, the unittests in CDM core need to call InitLogging
// to be able to control verbose logging in command line.
void InitLogging(int argc, const char* const* argv);

void Log(const char* file, int line, LogPriority level, const char* fmt, ...);

// Log APIs
#define LOGE(...) Log(__FILE__, __LINE__, wvcdm::LOG_ERROR, __VA_ARGS__)
#define LOGW(...) Log(__FILE__, __LINE__, wvcdm::LOG_WARN, __VA_ARGS__)
#define LOGI(...) Log(__FILE__, __LINE__, wvcdm::LOG_INFO, __VA_ARGS__)
#define LOGD(...) Log(__FILE__, __LINE__, wvcdm::LOG_DEBUG, __VA_ARGS__)
#define LOGV(...) Log(__FILE__, __LINE__, wvcdm::LOG_VERBOSE, __VA_ARGS__)

};  // namespace wvcdm

#endif  // CDM_BASE_LOG_H_
