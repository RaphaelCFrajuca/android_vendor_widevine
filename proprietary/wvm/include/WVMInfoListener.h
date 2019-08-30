/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#ifndef WVMINFO_LISTENER_H

#define WVMINFO_LISTENER_H

#include "AndroidConfig.h"
#include "WVMMediaSource.h"
#include <media/stagefright/DataSource.h>
#include "WVStreamControlAPI.h"
#include <utils/RefBase.h>


namespace android {

// Handles messages from the DRM plugin
class WVMInfoListener : public DrmManagerClient::OnInfoListener {
        enum MessageType {
            MessageType_HeartbeatServer = 4000,
            MessageType_HeartbeatPeriod = 4001,
            MessageType_AssetId = 4002,
            MessageType_DeviceId = 4003,
            MessageType_StreamId = 4004,
            MessageType_UserData = 4005
        };

    public:
        WVMInfoListener() : mSession(NULL), mHaveInfo(false){};
        virtual void onInfo(const DrmInfoEvent &event);
        void setSession(WVSession *session);
        void configureHeartbeat();

    private:
        WVSession *mSession;
        uint32_t mAssetId;
        std::string mServerUrl;
        std::string mStreamId;
        std::string mDeviceId;
        std::string mUserData;
        int mPeriod;
        bool mHaveInfo;
};

}  // namespace android

#endif  // WVMINFO_LISTENER_H
