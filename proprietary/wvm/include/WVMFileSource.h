/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#ifndef WVFILE_SOURCE_H_
#define WVFILE_SOURCE_H_

#include "AndroidConfig.h"
#include "WVStreamControlAPI.h"
#include <media/stagefright/DataSource.h>
#include <utils/RefBase.h>

//
// Supports reading data from local file descriptor instead of URI-based streaming
// as we normally do.
//

namespace android {

class WVMFileSource : public WVFileSource, public RefBase {
public:
    WVMFileSource(sp<DataSource> &dataSource);
    virtual ~WVMFileSource() {}

    virtual unsigned long long GetSize();
    virtual unsigned long long GetOffset();

    virtual void Seek(unsigned long long offset);
    virtual size_t Read(size_t amount, unsigned char *buffer);

private:
    sp<DataSource> mDataSource;
    unsigned long long mOffset;
    bool mLogOnce;
};

};


#endif
