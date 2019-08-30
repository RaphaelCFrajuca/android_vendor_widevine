/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#define LOG_TAG "WVMFileSource"
#include <utils/Log.h>

#include "WVMFileSource.h"
#include "media/stagefright/MediaErrors.h"
#include "media/stagefright/MediaDefs.h"

namespace android {


WVMFileSource::WVMFileSource(sp<DataSource> &dataSource)
    : mDataSource(dataSource),
      mOffset(0), mLogOnce(true)
{
}

unsigned long long WVMFileSource::GetSize()
{
    off64_t size;
    mDataSource->getSize(&size);
    return size;
}

unsigned long long WVMFileSource::GetOffset()
{
    return mOffset;
}

void WVMFileSource::Seek(unsigned long long offset)
{
    mOffset = offset;
}

size_t WVMFileSource::Read(size_t amount, unsigned char *buffer)
{
    ssize_t result = mDataSource->readAt(mOffset, buffer, amount);

    if (result < 0) {
        if (mLogOnce) {
            ALOGE("mDataSource-readAt returned error %d\n", (int)result );
            mLogOnce = false;
        }
        result = 0;
    } else  {
        mOffset += result;
        mLogOnce = true;
    }

    return result;
}

} // namespace android
