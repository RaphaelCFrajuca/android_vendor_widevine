/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <iostream>

#include "WVMDrmPlugin.h"
#include "drm/DrmInfoRequest.h"
#include "drm/DrmInfoStatus.h"
#include "drm/DrmConstraints.h"
#include "drm/DrmInfo.h"

using namespace android;
using namespace std;

class WVMDrmPluginTest
{
public:
    WVMDrmPluginTest() {}
    ~WVMDrmPluginTest() {}

    void TestAsset(IDrmEngine *plugin, String8 &url, bool useOpenFd = false);

    void TestRegister(IDrmEngine *plugin);
    void TestAcquireRights(IDrmEngine *plugin, String8 &url, int playbackMode,
                           bool useOpenFd = false);
    void TestCheckRightsNotAcquired(IDrmEngine *plugin, String8 &url);
    void TestCheckValidRights(IDrmEngine *plugin, String8 &url);
    void TestGetConstraints(IDrmEngine *plugin, String8 &url, int playbackMode);
    void TestRemoveRights(IDrmEngine *plugin, String8 &url);
    void TestRemoveAllRights(IDrmEngine *plugin);

    // Tests
    void Run();

private:
    static const int PlaybackMode_Default = 0;
    static const int PlaybackMode_Streaming = 1;
    static const int PlaybackMode_Offline = 2;
    static const int PlaybackMode_Any = PlaybackMode_Streaming | PlaybackMode_Offline;
};

void WVMDrmPluginTest::Run()
{
    cout << "WVDrmPluginTest::Run" << endl;
    const char *path = "/vendor/lib/drm/libdrmwvmplugin.so";
    void *handle = dlopen(path, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "Can't open plugin: %s %s\n", path, dlerror());
        exit(-1);
    }

    typedef IDrmEngine *(*create_t)();
    create_t creator = (create_t)dlsym(handle, "create");
    if (!creator) {
        fprintf(stderr, "Can't find create method\n");
        exit(-1);
    }

    typedef void (*destroy_t)(IDrmEngine *);
    destroy_t destroyer = (destroy_t)dlsym(handle, "destroy");
    if (!destroyer) {
        fprintf(stderr, "Can't find destroy method\n");
        exit(-1);
    }

    // Basic test - see if we can instantiate the object and call a method
    IDrmEngine *plugin = (*creator)();
    if (plugin->initialize(0) != DRM_NO_ERROR) {
        fprintf(stderr, "onInitialize failed!\n");
        exit(-1);
    }


    String8 url;

    // Remote asset
    url = String8("http://seawwws001.cdn.shibboleth.tv/videos/content/bbb_ffmpeg_hc_single_480p.wvm");
    TestAsset(plugin, url);

    // Remote asset using widevine:// protocol
    url = String8("widevine://seawwws001.cdn.shibboleth.tv/videos/content/bbb_ffmpeg_hc_single_480p.wvm");
    TestAsset(plugin, url);

    // Local asset using URL syntax
    url = String8("file:///sdcard/Widevine/inception_base_360p_single.wvm");
    TestAsset(plugin, url);

    // Local asset using normal file path
    url = String8("/sdcard/Widevine/inception_base_360p_single.wvm");
    TestAsset(plugin, url);

    // Local asset, but also supply open file descriptor
    url = String8("/sdcard/Widevine/inception_base_360p_single.wvm");
    TestAsset(plugin, url, true);

    // Remote asset with query parameters
    url = String8("http://seawwws001.cdn.shibboleth.tv/videos/content/bbb_ffmpeg_hc_single_480p.wvm?a=b");
    TestAsset(plugin, url);

    // Shut down and clean up
    if (plugin->terminate(0) != DRM_NO_ERROR) {
        fprintf(stderr, "onTerminate failed!\n");
        exit(-1);
    }
    destroyer(plugin);
    dlclose(handle);
    printf("Test successful!\n");
    exit(0);
}

void WVMDrmPluginTest::TestRegister(IDrmEngine *plugin)
{
    cout << "WVDrmPluginTest::TestRegister" << endl;

    String8 mimeType("video/wvm");
    DrmInfoRequest registrationInfo(DrmInfoRequest::TYPE_REGISTRATION_INFO, mimeType);
    registrationInfo.put(String8("WVPortalKey"), String8("OEM"));

    DrmInfo *info = plugin->acquireDrmInfo(0, &registrationInfo);
    if (info == NULL) {
        fprintf(stderr, "acquireDrmInfo failed!\n");
        exit(-1);
    }
    delete info;
}

void WVMDrmPluginTest::TestAcquireRights(IDrmEngine *plugin, String8 &url,
                                         int playbackMode, bool useOpenFd)
{
    cout << "WVDrmPluginTest::TestAcquireRights url=" << url << " mode=" <<
        playbackMode << " useOpenFd=" << useOpenFd << endl;

    int openFd = -1;

    String8 mimeType("video/wvm");
    DrmInfoRequest rightsAcquisitionInfo(DrmInfoRequest::TYPE_RIGHTS_ACQUISITION_INFO, mimeType);
    rightsAcquisitionInfo.put(String8("WVDRMServerKey"), String8(
        "https://staging.shibboleth.tv/widevine/cypherpc/cgi-bin/GetEMMs.cgi"));
    rightsAcquisitionInfo.put(String8("WVAssetURIKey"), url);

    if (useOpenFd) {
        char openFdStr[16];
        openFd = open(url.string(), O_RDONLY);
        if (openFd == -1) {
            cout << "error opening " << url << ":" << endl;
            fprintf(stderr, "Couldn't open local asset file\n");
            exit(-1);
        }
        sprintf(openFdStr, "%lu", (unsigned long)openFd);
        rightsAcquisitionInfo.put(String8("FileDescriptorKey"), String8(openFdStr));
    }

    rightsAcquisitionInfo.put(String8("WVDeviceIDKey"), String8("device1234"));
    rightsAcquisitionInfo.put(String8("WVPortalKey"), String8("OEM"));
    if (playbackMode) {
        char num[4];
        sprintf(num, "%d", playbackMode);
        rightsAcquisitionInfo.put(String8("WVLicenseTypeKey"), String8(num));
        cout << "WVLicenseTypeKey = " << num << endl;
    }

    DrmInfo *info = plugin->acquireDrmInfo(0, &rightsAcquisitionInfo);
    if (info == NULL) {
        fprintf(stderr, "acquireDrmInfo failed!\n");
        exit(-1);
    }

    if (useOpenFd && (openFd != -1)) {
        close(openFd);
    }

    DrmInfoStatus *status = plugin->processDrmInfo(0, info);
    if (status == NULL || status->statusCode != DrmInfoStatus::STATUS_OK) {
        fprintf(stderr, "processDrmInfo failed!\n");
        exit(-1);
    }

    delete status;
    delete info;
}

void WVMDrmPluginTest::TestCheckRightsNotAcquired(IDrmEngine *plugin, String8 &url)
{
    cout << "WVDrmPluginTest::TestCheckRightsNotAcquired url=" << url << endl;

    if (plugin->checkRightsStatus(0, url, Action::DEFAULT) != RightsStatus::RIGHTS_NOT_ACQUIRED) {
        fprintf(stderr, "checkRightsNotAcquired default action failed!\n");
        exit(-1);
    }

    if (plugin->checkRightsStatus(0, url, Action::PLAY) != RightsStatus::RIGHTS_NOT_ACQUIRED) {
        fprintf(stderr, "checkRightsNotAcquired failed!\n");
        exit(-1);
    }
}

void WVMDrmPluginTest::TestCheckValidRights(IDrmEngine *plugin, String8 &url)
{
    cout << "WVDrmPluginTest::TestCheckValidRights url=" << url << endl;

    if (plugin->checkRightsStatus(0, url, Action::DEFAULT) != RightsStatus::RIGHTS_VALID) {
        fprintf(stderr, "checkValidRights default action failed!\n");
        exit(-1);
    }

    if (plugin->checkRightsStatus(0, url, Action::PLAY) != RightsStatus::RIGHTS_VALID) {
        fprintf(stderr, "checkValidRights play action failed!\n");
        exit(-1);
    }
}

void WVMDrmPluginTest::TestGetConstraints(IDrmEngine *plugin, String8 &url, int playbackMode)
{
    cout << "WVDrmPluginTest::TestGetConstraints url=" << url << endl;

    DrmConstraints *constraints;
    constraints = plugin->getConstraints(0, &url, Action::PLAY);
    if (constraints == NULL) {
        fprintf(stderr, "getConstraints returned NULL constraints!\n");
        exit(-1);
    }

    if (constraints->getCount() != 6) {
        fprintf(stderr, "getConstraints returned unexpected count: %d!\n", constraints->getCount());
        exit(-1);
    }

    if (constraints->get(DrmConstraints::LICENSE_START_TIME) == "") {
        fprintf(stderr, "getConstraints missing start time!\n");
        exit(-1);
    }

    if (constraints->get(DrmConstraints::LICENSE_AVAILABLE_TIME) == "") {
        fprintf(stderr, "getConstraints missing available time!\n");
        exit(-1);
    }

    if (constraints->get(DrmConstraints::LICENSE_EXPIRY_TIME) == "") {
        fprintf(stderr, "getConstraints missing expiry time!\n");
        exit(-1);
    }

    if (constraints->get(String8("WVLicenseTypeKey")) == "") {
        fprintf(stderr, "getConstraints missing license type key!\n");
        exit(-1);
    }

    if (constraints->get(String8("WVLicensedResolutionKey")) == "") {
        fprintf(stderr, "getConstraints missing resolution key!\n");
        exit(-1);
    }

    if (constraints->get(String8("WVLastErrorKey")) == "") {
        fprintf(stderr, "getConstraints missing last error key!\n");
        exit(-1);
    }

    String8 licenseTypeStr = constraints->get(String8("WVLicenseTypeKey"));
    int licenseType = atol(licenseTypeStr.string());
    if (licenseType != playbackMode) {
        fprintf(stderr, "license type mismatch, expected %d, found %d\n", playbackMode, licenseType);
        exit(-1);
    }

    delete constraints;
}

void WVMDrmPluginTest::TestRemoveRights(IDrmEngine *plugin, String8 &url)
{
    cout << "WVDrmPluginTest::TestRemoveRights url=" << url << endl;

    status_t status = plugin->removeRights(0, url);
    if (status != DRM_NO_ERROR) {
        fprintf(stderr, "removeRights returned error: %d!\n", (int)status);
        exit(-1);
    }
}

void WVMDrmPluginTest::TestRemoveAllRights(IDrmEngine *plugin)
{
    cout << "WVDrmPluginTest::TestRemoveAllRights" << endl;

    status_t status = plugin->removeAllRights(0);
    if (status != DRM_NO_ERROR) {
        fprintf(stderr, "removeAllRights returned error: %d!\n", (int)status);
        exit(-1);
    }
}

void WVMDrmPluginTest::TestAsset(IDrmEngine *plugin, String8 &url,
                                 bool useOpenFd)
{
    cout << "WVDrmPluginTest::TestAsset url=" << url <<
        " useOpenFd=" << useOpenFd << endl;

    TestRegister(plugin);
    TestRemoveAllRights(plugin);
    TestCheckRightsNotAcquired(plugin, url);

    TestAcquireRights(plugin, url, PlaybackMode_Default, useOpenFd);
    TestCheckValidRights(plugin, url);
    TestGetConstraints(plugin, url, PlaybackMode_Any);
    TestRemoveRights(plugin, url);
    TestCheckRightsNotAcquired(plugin, url);

    TestAcquireRights(plugin, url, PlaybackMode_Offline, useOpenFd);
    TestCheckValidRights(plugin, url);
    TestGetConstraints(plugin, url, PlaybackMode_Offline);
    TestRemoveRights(plugin, url);
    TestCheckRightsNotAcquired(plugin, url);

    TestAcquireRights(plugin, url, PlaybackMode_Streaming, useOpenFd);
    TestCheckValidRights(plugin, url);
    TestGetConstraints(plugin, url, PlaybackMode_Streaming);
    TestRemoveRights(plugin, url);
    TestCheckRightsNotAcquired(plugin, url);

    TestAcquireRights(plugin, url, PlaybackMode_Any, useOpenFd);
    TestCheckValidRights(plugin, url);
    TestGetConstraints(plugin, url, PlaybackMode_Any);
    TestRemoveRights(plugin, url);
    TestCheckRightsNotAcquired(plugin, url);
}

int main(int argc, char **argv)
{
    // turn off some noisy printing in WVStreamControl
    setenv("WV_SILENT", "true", 1);

    WVMDrmPluginTest test;
    test.Run();
}
