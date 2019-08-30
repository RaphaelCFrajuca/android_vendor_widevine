/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#define LOG_TAG "WVMLogging"
#include <utils/Log.h>
#include "WVMLogging.h"

// Connect Widevine debug logging into Android logging

void android_printbuf(const char *buf)
{
    ALOGD("%s", buf);
}
