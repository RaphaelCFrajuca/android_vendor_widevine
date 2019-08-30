/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

#ifndef __WVMDRMPLUGIN_H__
#define __WVMDRMPLUGIN_H__


#include <AndroidConfig.h>
#include <DrmEngineBase.h>

#include "WVDRMPluginAPI.h"


namespace android {

    class WVMDrmPlugin : public DrmEngineBase
    {

public:
    WVMDrmPlugin();
    virtual ~WVMDrmPlugin();

protected:
    DrmConstraints* onGetConstraints(int uniqueId, const String8* path, int action);

    DrmMetadata* onGetMetadata(int uniqueId, const String8* path);

    status_t onInitialize(int uniqueId);

    status_t onSetOnInfoListener(int uniqueId, const IDrmEngine::OnInfoListener* infoListener);

    status_t onTerminate(int uniqueId);

    bool onCanHandle(int uniqueId, const String8& path);

    DrmInfoStatus* onProcessDrmInfo(int uniqueId, const DrmInfo* drmInfo);

    status_t onSaveRights(int uniqueId, const DrmRights& drmRights,
            const String8& rightsPath, const String8& contentPath);

    DrmInfo* onAcquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest);

    String8 onGetOriginalMimeType(int uniqueId, const String8& path, int fd);

    int onGetDrmObjectType(int uniqueId, const String8& path, const String8& mimeType);

    int onCheckRightsStatus(int uniqueId, const String8& path, int action);

    status_t onConsumeRights(int uniqueId, DecryptHandle* decryptHandle, int action, bool reserve);

    status_t onSetPlaybackStatus(
            int uniqueId, DecryptHandle* decryptHandle, int playbackStatus, off64_t position);

    bool onValidateAction(
            int uniqueId, const String8& path, int action, const ActionDescription& description);

    status_t onRemoveRights(int uniqueId, const String8& path);

    status_t onRemoveAllRights(int uniqueId);

    status_t onOpenConvertSession(int uniqueId, int convertId);

    DrmConvertedStatus* onConvertData(int uniqueId, int convertId, const DrmBuffer* inputData);

    DrmConvertedStatus* onCloseConvertSession(int uniqueId, int convertId);

    DrmSupportInfo* onGetSupportInfo(int uniqueId);

    status_t onOpenDecryptSession(int uniqueId, DecryptHandle *decryptHandle,
                                  int fd, off64_t offset, off64_t length) {
        return DRM_ERROR_CANNOT_HANDLE;
    }

    status_t onOpenDecryptSession(int uniqueId, DecryptHandle *decryptHandle,
                                  int fd, off64_t offset, off64_t length,
                                  const char* mime);

    status_t onOpenDecryptSession(int uniqueId, DecryptHandle *decryptHandle,
                                  const char* uri) {
        return DRM_ERROR_CANNOT_HANDLE;
    }

    status_t onOpenDecryptSession(int uniqueId, DecryptHandle *decryptHandle,
                                  const char* uri,
                                  const char* mime);

    status_t onCloseDecryptSession(int uniqueId, DecryptHandle* decryptHandle);

    status_t onInitializeDecryptUnit(int uniqueId, DecryptHandle* decryptHandle,
                                     int decryptUnitId, const DrmBuffer* headerInfo);

    status_t onDecrypt(int uniqueId, DecryptHandle* decryptHandle, int decryptUnitId,
                       const DrmBuffer* encBuffer, DrmBuffer** decBuffer,
                       DrmBuffer *ivBuffer);


    status_t onFinalizeDecryptUnit(int uniqueId, DecryptHandle* decryptHandle, int decryptUnitId);

    ssize_t onPread(int uniqueId, DecryptHandle* decryptHandle,
            void* buffer, ssize_t numBytes, off64_t offset);

    class Listener {
    public:
        Listener() : mListener(NULL), mUniqueId(-1) {}

        Listener(IDrmEngine::OnInfoListener *listener, int uniqueId)
            : mListener(listener), mUniqueId(uniqueId) {};

        IDrmEngine::OnInfoListener *GetListener() const {return mListener;}
        int GetUniqueId() const {return mUniqueId;}

    private:
        IDrmEngine::OnInfoListener *mListener;
        int mUniqueId;
    };

    enum MessageType {
        MessageType_HeartbeatServer = 4000,
        MessageType_HeartbeatPeriod = 4001,
        MessageType_AssetId = 4002,
        MessageType_DeviceId = 4003,
        MessageType_StreamId = 4004,
        MessageType_UserData = 4005
    };

private:
    bool isSupportedMimeType(const char* mime);
    static bool SendEvent(WVDRMPluginAPI::EventType code, WVDRMPluginAPI::EventDestination dest,
                          const std::string &path);

    static Vector<Listener> *sNativeListeners;
    static Vector<Listener> *sJavaAPIListeners;
    static const char *sFileExtensions[];

    WVDRMPluginAPI *mDrmPluginImpl;
};

};

#endif /* __WVMDRMPLUGIN__ */
