/*
 * Copyright 2011 Widevine Technologies, Inc., All Rights Reserved
 *
 * Declarations for Widevine DRM Plugin API
 */

#ifndef __WVMDRMPLUGIN_API_H__
#define __WVMDRMPLUGIN_API_H__

#include <string>
#include "WVStreamControlAPI.h"

class WVDRMPluginAPI {
 public:
    virtual ~WVDRMPluginAPI() {}

    enum {
        RIGHTS_VALID,
        RIGHTS_INVALID,
        RIGHTS_EXPIRED,
        RIGHTS_NOT_ACQUIRED
    };

    enum {
        PLAYBACK_START,
        PLAYBACK_STOP,
        PLAYBACK_PAUSE,
        PLAYBACK_INVALID
    };

    // provisionedFlags
    enum {
        DEVICE_IS_PROVISIONED,
        DEVICE_IS_NOT_PROVISIONED,
        DEVICE_IS_PROVISIONED_SD_ONLY
    };

    static const int PlaybackMode_Default = 0;
    static const int PlaybackMode_Streaming = 1;
    static const int PlaybackMode_Offline = 2;
    static const int PlaybackMode_Any = PlaybackMode_Streaming |
                                        PlaybackMode_Offline;

    static WVDRMPluginAPI *create();
    static void destroy(WVDRMPluginAPI *plugin);

    virtual bool OpenSession(const char *uri) = 0;
    virtual void CloseSession() = 0;
    virtual bool IsSupportedMediaType(const char *uri) = 0;

    virtual bool RegisterDrmInfo(std::string &portal, std::string &dsPath) = 0;
    virtual bool RegisterDrmInfo(std::string &portal, std::string &dsPath, uint32_t *status) = 0;
    virtual bool UnregisterDrmInfo(std::string &portal, std::string &dsPath) = 0;
    virtual bool AcquireDrmInfo(std::string &assetPath, int assetOpenFd, WVCredentials &credentials,
                                std::string &dsPath, const std::string &systemIdStr,
                                const std::string &assetIdStr,
                                const std::string &keyIdStr,
                                uint32_t *systemId, uint32_t *assetId,
                                uint32_t *keyId) = 0;

    virtual bool ProcessDrmInfo(std::string &assetPath, int playbackMode) = 0;
    virtual int CheckRightsStatus(std::string &path) = 0;

    virtual bool GetConstraints(std::string &path, uint32_t *timeSincePlayback,
                                uint32_t *timeRemaining,
                                uint32_t *licenseDuration, std::string &lastError,
                                bool &allowOffline, bool &allowStreaming,
                                bool &denyHD) = 0;

    virtual bool SetPlaybackStatus(int playbackStatus, off64_t position) = 0;
    virtual bool RemoveRights(std::string &path) = 0;
    virtual bool RemoveAllRights() = 0;
    virtual bool Prepare(char *data, int len) = 0;
    virtual int Operate(char *in, int inLength, char *out, int outLength, char *iv) = 0;
    virtual std::string GetVersion() const = 0;

    enum EventType {
        EventType_AcquireDrmInfoFailed,
        EventType_ProcessDrmInfoFailed,
        EventType_RightsInstalled,
        EventType_RightsRemoved,

        EventType_HeartbeatServer,
        EventType_HeartbeatPeriod,
        EventType_AssetId,
        EventType_DeviceId,
        EventType_StreamId,
        EventType_UserData
    };

    enum EventDestination {
        EventDestination_JavaAPI,
        EventDestination_MediaPlayer
    };

    // Returns true if event sent, false if no handler
    typedef bool (*EventHandler)(EventType type, EventDestination destination,
                                 const std::string &path);
    virtual void SetEventHandler(EventHandler handler) = 0;

protected:
    // use create factory method, don't construct directly
    WVDRMPluginAPI() {}
};

#endif
