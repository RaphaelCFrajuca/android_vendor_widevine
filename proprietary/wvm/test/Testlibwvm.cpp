/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#include <dlfcn.h>
#include <iostream>

#include "include/WVMExtractor.h"
#include <media/stagefright/Utils.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/FileSource.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MediaBuffer.h>

using namespace android;
using namespace std;

class TestLibWVM
{
public:
    TestLibWVM() {}
    ~TestLibWVM() {}

    // Tests
    void Load();
};

DrmManagerClient* gDrmManagerClient;

// This test just confirms that there are no unresolved symbols in libwvm and we
// can locate the entry point.

void TestLibWVM::Load()
{
    cout << "TestLibWVM::Load" << endl;

    const char *path = "/vendor/lib/libwvm.so";
    void *handle = dlopen(path, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Can't open plugin: %s: %s\n", path, dlerror());
        exit(-1);
    }

    typedef MediaExtractor *(*GetInstanceFunc)(sp<DataSource>);
    GetInstanceFunc getInstanceFunc =
        (GetInstanceFunc) dlsym(handle,
                "_ZN7android11GetInstanceENS_2spINS_10DataSourceEEE");

    // Basic test - just see if we can instantiate the object and call a method
    if (getInstanceFunc) {
        ALOGD("Found GetInstanceFunc");
    } else {
        ALOGE("Failed to locate GetInstance in libwvm.so");
    }

    dlclose(handle);
    printf("Test successful!\n");
    exit(0);
}

int main(int argc, char **argv)
{
    TestLibWVM test;
    test.Load();
}
