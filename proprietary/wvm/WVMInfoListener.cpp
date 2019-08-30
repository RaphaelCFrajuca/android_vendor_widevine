/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#define LOG_TAG "WVMInfoListener"
#include <utils/Log.h>

#include "WVMExtractorImpl.h"
#include "WVMMediaSource.h"
#include "WVMFileSource.h"
#include "WVMInfoListener.h"
#include "WVMLogging.h"
#include "WVStreamControlAPI.h"
#include "media/stagefright/MediaErrors.h"
#include "media/stagefright/MediaDefs.h"
#include "drm/DrmInfoEvent.h"


namespace android {

void WVMInfoListener::setSession(WVSession *session)
{
    mSession = session;
}

void WVMInfoListener::onInfo(const DrmInfoEvent &event)
{
    //ALOGD("WVMMediaSource::onInfo: type=%d, msg=%s!!!",
    //     event.getType(), event.getMessage().string());

    if (event.getType() == MessageType_HeartbeatServer)
        mServerUrl = event.getMessage();
    else if (event.getType() == MessageType_HeartbeatPeriod)
        mPeriod = atoi(event.getMessage());
    else if (event.getType() == MessageType_AssetId)
        mAssetId = atoi(event.getMessage());
    else if (event.getType() == MessageType_DeviceId)
        mDeviceId = event.getMessage();
    else if (event.getType() == MessageType_StreamId)
        mStreamId = event.getMessage();
    else if (event.getType() == MessageType_UserData) {
        mUserData = event.getMessage();
        mHaveInfo = true;
    }
}

void WVMInfoListener::configureHeartbeat()
{
    // send the first time we have all the info
    if (mSession && mHaveInfo) {
        //ALOGD("WVMMediaSource::calling WV_ConfigureHeartbeat()");
        WV_ConfigureHeartbeat(mSession, mServerUrl, mPeriod, mAssetId,
                              mDeviceId, mStreamId, mUserData);
        mSession = NULL;
    }
}

};

