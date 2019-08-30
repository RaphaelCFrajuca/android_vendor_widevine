/*
 * Copyright (C) 2011 Google, Inc.  All Rights Reserved
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "WVMDrmPlugIn"
#include <utils/Log.h>
#include <vector>

#include <drm/DrmRights.h>
#include <drm/DrmConstraints.h>
#include <drm/DrmInfo.h>
#include <drm/DrmInfoEvent.h>
#include <drm/DrmInfoStatus.h>
#include <drm/DrmConvertedStatus.h>
#include <drm/DrmInfoRequest.h>
#include <drm/DrmSupportInfo.h>
#include <drm/DrmMetadata.h>

#include "WVMDrmPlugin.h"
#include "WVMLogging.h"
#include "AndroidHooks.h"

using namespace std;
using namespace android;


// This extern "C" is mandatory to be managed by TPlugInManager
extern "C" IDrmEngine* create() {
    _ah006(android_printbuf);
    libocs_setup();
    return new WVMDrmPlugin();
}

// This extern "C" is mandatory to be managed by TPlugInManager
extern "C" void destroy(IDrmEngine* pPlugIn) {
    delete pPlugIn;
}

// Needed for event callout from implementation object
Vector<WVMDrmPlugin::Listener> *WVMDrmPlugin::sNativeListeners = NULL;
Vector<WVMDrmPlugin::Listener> *WVMDrmPlugin::sJavaAPIListeners = NULL;

// File extensions that Widevine can handle.
// Note: the empty extension is needed because some proxy servers will strip the extension.
const char *WVMDrmPlugin::sFileExtensions[] = {".wvm", ".m3u8", ".vob", ".smil", "", NULL};


WVMDrmPlugin::WVMDrmPlugin()
    : DrmEngineBase(),
      mDrmPluginImpl(WVDRMPluginAPI::create())
{
    sNativeListeners = new Vector<WVMDrmPlugin::Listener>();
    sJavaAPIListeners = new Vector<WVMDrmPlugin::Listener>();
    mDrmPluginImpl->SetEventHandler(&SendEvent);
}

WVMDrmPlugin::~WVMDrmPlugin() {
    delete sNativeListeners;
    delete sJavaAPIListeners;
    WVDRMPluginAPI::destroy(mDrmPluginImpl);
}


/**
 * Initialize plug-in
 *
 * @param[in] uniqueId Unique identifier for a session
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onInitialize(int uniqueId) {
    //ALOGD("WVMDrmPlugin::onInitialize : %d", uniqueId);
    return DRM_NO_ERROR;
}

/**
 * Terminate the plug-in
 * and release resource bound to plug-in
 *
 * @param[in] uniqueId Unique identifier for a session
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onTerminate(int uniqueId) {
    //ALOGD("WVMDrmPlugin::onTerminate : %d", uniqueId);

    for (size_t i = 0; i < sNativeListeners->size(); i++) {
        if ((*sNativeListeners)[i].GetUniqueId() == uniqueId) {
            sNativeListeners->removeAt(i);
            break;
        }
    }

    for (size_t i = 0; i < sJavaAPIListeners->size(); i++) {
        if ((*sJavaAPIListeners)[i].GetUniqueId() == uniqueId) {
            sJavaAPIListeners->removeAt(i);
            break;
        }
    }

    return DRM_NO_ERROR;
}

/**
 * Register a callback to be invoked when the caller required to
 * receive necessary information
 *
 * @param[in] uniqueId Unique identifier for a session. uniqueId is a random
 *                     number generated in the DRM service. If the DrmManagerClient
 *                     is created in native code, uniqueId will be a number ranged
 *                     from 0x1000 to 0x1fff. If it comes from Java code, the uniqueId
 *                     will be a number ranged from 0x00 to 0xfff. So bit 0x1000 in
 *                     uniqueId could be used in DRM plugins to differentiate native
 *                     OnInfoListener and Java OnInfoListener.
 * @param[in] infoListener Listener
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onSetOnInfoListener(
    int uniqueId, const IDrmEngine::OnInfoListener* infoListener) {
    //ALOGD("WVMDrmPlugin::onSetOnInfoListener : add %d", uniqueId);

    Listener newListener = Listener(const_cast<IDrmEngine::OnInfoListener *>(infoListener), uniqueId);
    bool found = false;

    const int nativeUniqueIdFlag = 0x1000;
    if (uniqueId & nativeUniqueIdFlag) {
        // Replace old listener for this id if it exists
        for (size_t i = 0; i < sNativeListeners->size(); i++) {
            if ((*sNativeListeners)[i].GetUniqueId() == uniqueId) {
                sNativeListeners->replaceAt(newListener, i);
                found = true;
                break;
            }
        }
        if (!found)
            sNativeListeners->push(newListener);
    } else {
        // Replace old listener for this id if it exists
        for (size_t i = 0; i < sJavaAPIListeners->size(); i++) {
            if ((*sJavaAPIListeners)[i].GetUniqueId() == uniqueId) {
                sJavaAPIListeners->replaceAt(newListener, i);
                found = true;
                break;
            }
        }
        if (!found)
            sJavaAPIListeners->push(newListener);
    }

    return DRM_NO_ERROR;
}

bool WVMDrmPlugin::SendEvent(WVDRMPluginAPI::EventType type,
                             WVDRMPluginAPI::EventDestination destination,
                             const std::string &msg)
{
    int code = -1;
    bool result = false;

    switch(type) {
    case WVDRMPluginAPI::EventType_AcquireDrmInfoFailed:
        code = DrmInfoEvent::TYPE_ACQUIRE_DRM_INFO_FAILED;
        break;
    case WVDRMPluginAPI::EventType_ProcessDrmInfoFailed:
        code = DrmInfoEvent::TYPE_PROCESS_DRM_INFO_FAILED;
        break;
    case WVDRMPluginAPI::EventType_RightsInstalled:
        code = DrmInfoEvent::TYPE_RIGHTS_INSTALLED;
        break;
    case WVDRMPluginAPI::EventType_RightsRemoved:
        code = DrmInfoEvent::TYPE_RIGHTS_REMOVED;
        break;
    case WVDRMPluginAPI::EventType_HeartbeatServer:
        code = MessageType_HeartbeatServer;
        break;
    case WVDRMPluginAPI::EventType_HeartbeatPeriod:
        code = MessageType_HeartbeatPeriod;
        break;
    case WVDRMPluginAPI::EventType_AssetId:
        code = MessageType_AssetId;
        break;
    case WVDRMPluginAPI::EventType_DeviceId:
        code = MessageType_DeviceId;
        break;
    case WVDRMPluginAPI::EventType_StreamId:
        code = MessageType_StreamId;
        break;
    case WVDRMPluginAPI::EventType_UserData:
        code = MessageType_UserData;
        break;
    default:
        break;
    }

    String8 message = String8(msg.c_str());

    if (destination == WVDRMPluginAPI::EventDestination_JavaAPI) {
        for (size_t i = 0; i < sJavaAPIListeners->size(); i++) {
            DrmInfoEvent event((*sJavaAPIListeners)[i].GetUniqueId(), code, message);
            //ALOGD("WVMDrmPlugin::SendEvent [Java]: uniqueId=%d type=%d, code=%d, msg=%s",
            //    (*sJavaAPIListeners)[i].GetUniqueId(), type, code, msg.c_str());
            (*sJavaAPIListeners)[i].GetListener()->onInfo(event);
        }
        result = true;
    } else if (destination == WVDRMPluginAPI::EventDestination_MediaPlayer) {
        for (size_t i = 0; i < sNativeListeners->size(); i++) {
            DrmInfoEvent event((*sNativeListeners)[i].GetUniqueId(), code, message);
            //ALOGD("WVMDrmPlugin::SendEvent [Native]: uniqueId=%d type=%d, code=%d, msg=%s",
            //    (*sNativeListeners)[i].GetUniqueId(), type, code, msg.c_str());
            (*sNativeListeners)[i].GetListener()->onInfo(event);
        }
        result = true;
    }

    return result;
}

/**
 * Retrieves necessary information for registration, unregistration or rights
 * acquisition information.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] drmInfoRequest Request information to retrieve drmInfo
 * @return DrmInfo
 *     instance as a result of processing given input
 */
DrmInfo* WVMDrmPlugin::onAcquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest) {
    //ALOGD("WVMDrmPlugin::onAcquireDrmInfo : %d", uniqueId);
    DrmInfo* drmInfo = NULL;

    std::string assetPath;

    if (NULL != drmInfoRequest) {
        switch(drmInfoRequest->getInfoType()) {
            case DrmInfoRequest::TYPE_RIGHTS_ACQUISITION_INFO: {

                assetPath = drmInfoRequest->get(String8("WVAssetURIKey")).string();

                WVCredentials credentials;

                // creates a data store object per each portal
                credentials.portal = drmInfoRequest->get(String8("WVPortalKey")).string();
                if ( (assetPath.size() == 0) || (credentials.portal.size() == 0) ) {
                    ALOGE("onAcquireDrmInfo: Empty asset path or portal string, must specify both");
                    return NULL;
                }

                // for local files, app may provide the FD of the open file.
                int assetOpenFd = atol(drmInfoRequest->get(String8("FileDescriptorKey")).string());

                std::string assetDbPath = drmInfoRequest->get(String8("WVAssetDBPathKey")).string();
                //ALOGV("onAcquireDrmInfo: portal=%s, dsPath=%s", credentials.portal.c_str(), assetDbPath.c_str());

                credentials.drmServerURL = drmInfoRequest->get(String8("WVDRMServerKey")).string();
                credentials.userData = drmInfoRequest->get(String8("WVCAUserDataKey")).string();
                credentials.deviceID = drmInfoRequest->get(String8("WVDeviceIDKey")).string();
                credentials.streamID = drmInfoRequest->get(String8("WVStreamIDKey")).string();

                string systemIdStr = drmInfoRequest->get(String8("WVSystemIDKey")).string();
                string assetIdStr = drmInfoRequest->get(String8("WVAssetIDKey")).string();
                string keyIdStr = drmInfoRequest->get(String8("WVKeyIDKey")).string();
                string licenseTypeStr = drmInfoRequest->get(String8("WVLicenseTypeKey")).string();

                uint32_t systemId, assetId, keyId;

                if (!mDrmPluginImpl->AcquireDrmInfo(assetPath, assetOpenFd, credentials, assetDbPath,
                                                    systemIdStr, assetIdStr, keyIdStr,
                                                    &systemId, &assetId, &keyId))
                    return NULL;


                String8 dataString("dummy_acquistion_string");
                int length = dataString.length();
                char* data = NULL;
                data = new char[length];
                memcpy(data, dataString.string(), length);
                drmInfo = new DrmInfo(drmInfoRequest->getInfoType(),
                                      DrmBuffer(data, length), drmInfoRequest->getMimeType());

                // Sets additional drmInfo attributes
                // Do not propagate FileDescriptorKey into the newDrmInfo object
                drmInfo->put(String8("WVAssetURIKey"), String8(assetPath.c_str()));
                drmInfo->put(String8("WVDRMServerKey"), String8(credentials.drmServerURL.c_str()));
                drmInfo->put(String8("WVAssetDbPathKey"), String8(assetDbPath.c_str()));
                drmInfo->put(String8("WVPortalKey"), String8(credentials.portal.c_str()));
                drmInfo->put(String8("WVCAUserDataKey"), String8(credentials.userData.c_str()));
                drmInfo->put(String8("WVDeviceIDKey"), String8(credentials.deviceID.c_str()));
                drmInfo->put(String8("WVStreamIDKey"), String8(credentials.streamID.c_str()));
                drmInfo->put(String8("WVLicenseTypeKey"), String8(licenseTypeStr.c_str()));

                char buffer[16];
                sprintf(buffer, "%lu", (unsigned long)systemId);
                drmInfo->put(String8("WVSystemIDKey"), String8(buffer));
                sprintf(buffer, "%lu", (unsigned long)assetId);
                drmInfo->put(String8("WVAssetIDKey"), String8(buffer));
                sprintf(buffer, "%lu", (unsigned long)keyId);
                drmInfo->put(String8("WVKeyIDKey"), String8(buffer));
                break;
            }
            case DrmInfoRequest::TYPE_REGISTRATION_INFO:
            case DrmInfoRequest::TYPE_UNREGISTRATION_INFO: {

                // creates a data store object per each portal
                std::string assetDbPath = drmInfoRequest->get(String8("WVAssetDBPathKey")).string();
                std::string portal = drmInfoRequest->get(String8("WVPortalKey")).string();
                uint32_t drmInfoRequestStatus = 0;

                if (portal.size() == 0) {
                    ALOGE("onAcquireDrmInfo: Must specify portal string for registration operations");
                    return NULL;
                }

                if (drmInfoRequest->getInfoType()==DrmInfoRequest::TYPE_REGISTRATION_INFO) {
                    if (!mDrmPluginImpl->RegisterDrmInfo(portal, assetDbPath, &drmInfoRequestStatus)) {
                        ALOGE("onAcquireDrmInfo: RegisterDrmInfo failed");
                        return NULL;
                    }
                } else {
                    if (!mDrmPluginImpl->UnregisterDrmInfo(portal, assetDbPath)) {
                        ALOGE("onAcquireDrmInfo: UnregisterDrmInfo failed");
                        return NULL;
                    }
                }

                String8 dataString("dummy_acquistion_string");
                int length = dataString.length();
                char* data = NULL;
                data = new char[length];
                memcpy(data, dataString.string(), length);
                drmInfo = new DrmInfo(drmInfoRequest->getInfoType(),
                        DrmBuffer(data, length), drmInfoRequest->getMimeType());

                if (drmInfoRequest->getInfoType()==DrmInfoRequest::TYPE_REGISTRATION_INFO) {
                    char buffer[16];
                    sprintf(buffer, "%lu", (unsigned long)drmInfoRequestStatus);
                    drmInfo->put(String8("WVDrmInfoRequestStatusKey"), String8(buffer));

                    drmInfo->put(String8("WVDrmInfoRequestVersionKey"),
                        String8(mDrmPluginImpl->GetVersion().c_str()));
                }
                break;
            }
            case DrmInfoRequest::TYPE_RIGHTS_ACQUISITION_PROGRESS_INFO: {
                ALOGE("onAcquireDrmInfo: Unsupported DrmInfoRequest type %d",
                     drmInfoRequest->getInfoType());
                break;
            }
            default: {
                ALOGE("onAcquireDrmInfo: Unknown info type %d", drmInfoRequest->getInfoType());
                break;
            }
        }
    }
    return drmInfo;
}

/**
 * Executes given drm information based on its type
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] drmInfo Information needs to be processed
 * @return DrmInfoStatus
 *     instance as a result of processing given input
 */
DrmInfoStatus* WVMDrmPlugin::onProcessDrmInfo(int uniqueId, const DrmInfo* drmInfo) {
    //ALOGD("WVMDrmPlugin::onProcessDrmInfo: %d", uniqueId);

    int status = DrmInfoStatus::STATUS_ERROR;

    if (NULL != drmInfo) {
        if (drmInfo->getInfoType() == DrmInfoRequest::TYPE_RIGHTS_ACQUISITION_INFO) {
            std::string assetPath = drmInfo->get(String8("WVAssetURIKey")).string();
            int playbackMode = atol(drmInfo->get(String8("WVLicenseTypeKey")).string());

            if (mDrmPluginImpl->ProcessDrmInfo(assetPath, playbackMode))
                status = DrmInfoStatus::STATUS_OK;
        } else if ((drmInfo->getInfoType() == DrmInfoRequest::TYPE_REGISTRATION_INFO) ||
              (drmInfo->getInfoType() == DrmInfoRequest::TYPE_UNREGISTRATION_INFO)) {
                status = DrmInfoStatus::STATUS_OK;
        } else {
            ALOGE("onProcessDrmInfo : drmInfo type %d not supported", drmInfo->getInfoType());
        }
    } else {
        ALOGE("onProcessDrmInfo : drmInfo cannot be NULL");
    }

    String8 licenseString("dummy_license_string");
    const int bufferSize = licenseString.size();
    char* data = NULL;
    data = new char[bufferSize];
    memcpy(data, licenseString.string(), bufferSize);
    const DrmBuffer* buffer = new DrmBuffer(data, bufferSize);
    DrmInfoStatus* drmInfoStatus =
            new DrmInfoStatus(status, drmInfo->getInfoType(), buffer, drmInfo->getMimeType());

    return drmInfoStatus;
}

/**
 * Get constraint information associated with input content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 * @param[in] action Actions defined such as,
 *     Action::DEFAULT, Action::PLAY, etc
 * @return DrmConstraints
 *     key-value pairs of constraint are embedded in it
 * @note
 *     In case of error, return NULL
 */
DrmConstraints* WVMDrmPlugin::onGetConstraints(int uniqueId, const String8* path, int action)
{
    //ALOGD("WVMDrmPlugin::onGetConstraints : %d", uniqueId);

    if ( (Action::DEFAULT != action) && (Action::PLAY != action) ) {
        ALOGE("onGetConstraints : action %d not supported", action);
        return NULL;
    }

    uint32_t licenseDuration = 0;
    uint32_t timeSincePlayback = 0;
    uint32_t timeRemaining = 0;
    std::string lastError;
    bool allowOffline;
    bool allowStreaming;
    bool denyHD;

    std::string assetPath(path->string());
    bool isValid = mDrmPluginImpl->GetConstraints(assetPath, &timeSincePlayback, &timeRemaining,
                                                  &licenseDuration, lastError, allowOffline,
                                                  allowStreaming, denyHD);

    DrmConstraints* drmConstraints =  new DrmConstraints();

    String8 key = String8("WVLastErrorKey");
    drmConstraints->put(&key, lastError.c_str());

    if (isValid) {
        char charValue[16]; // max uint32 + terminating char

        memset(charValue, 0, 16);
        sprintf(charValue, "%lu", (unsigned long)timeSincePlayback);
        drmConstraints->put(&(DrmConstraints::LICENSE_START_TIME), charValue);

        memset(charValue, 0, 16);
        sprintf(charValue, "%lu", (unsigned long)timeRemaining);
        drmConstraints->put(&(DrmConstraints::LICENSE_EXPIRY_TIME), charValue);

        memset(charValue, 0, 16);
        sprintf(charValue, "%lu", (unsigned long)licenseDuration);
        drmConstraints->put(&(DrmConstraints::LICENSE_AVAILABLE_TIME), charValue);

        key = String8("WVLicenseTypeKey");
        sprintf(charValue, "%u", (allowStreaming ? 1 : 0) | (allowOffline ? 2 : 0));
        drmConstraints->put(&key, charValue);

        key = String8("WVLicensedResolutionKey");
        sprintf(charValue, "%u", (denyHD ? 1 : 2));
        drmConstraints->put(&key, charValue);
    }

    return drmConstraints;
}


/**
 * Returns the information about the Drm Engine capabilities which includes
 * supported MimeTypes and file suffixes.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @return DrmSupportInfo
 *     instance which holds the capabilities of a plug-in
 */
DrmSupportInfo* WVMDrmPlugin::onGetSupportInfo(int uniqueId) {
    //ALOGD("WVMDrmPlugin::onGetSupportInfo : %d", uniqueId);
    DrmSupportInfo* drmSupportInfo = new DrmSupportInfo();
    // Add mimetype's
    drmSupportInfo->addMimeType(String8("video/wvm"));
    // Add File Suffixes
    for (int i=0; sFileExtensions[i]; i++) {
      drmSupportInfo->addFileSuffix(String8(sFileExtensions[i]));
    }
    // Add plug-in description
    drmSupportInfo->setDescription(String8("Widevine DRM plug-in"));
    return drmSupportInfo;
}

/**
 * Get meta data from protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 *
 * @return DrmMetadata
 *      key-value pairs of meta data; NULL if failed
 */
DrmMetadata* WVMDrmPlugin::onGetMetadata(int uniqueId, const String8* path) {
    //ALOGD("WVDrmPlugin::onGetMetadata returns NULL\n");
    return NULL;
}

/**
 * Save DRM rights to specified rights path
 * and make association with content path
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] drmRights DrmRights to be saved
 * @param[in] rightsPath File path where rights to be saved
 * @param[in] contentPath File path where content was saved
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onSaveRights(int uniqueId, const DrmRights& drmRights,
            const String8& rightsPath, const String8& contentPath) {
    //ALOGD("WVMDrmPlugin::onSaveRights : %d", uniqueId);
    return DRM_NO_ERROR;
}

/**
 * Get whether the given content can be handled by this plugin or not
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path the protected object
 * @return bool
 *     Returns true if this plugin can handle , false in case of not able to handle
 */
bool WVMDrmPlugin::onCanHandle(int uniqueId, const String8& path) {
    //ALOGD("WVMDrmPlugin::canHandle('%s') ", path.string());
    String8 extension = path.getPathExtension();
    extension.toLower();
    for (int i=0; sFileExtensions[i]; i++) {
        if (String8(sFileExtensions[i]) == extension) {
            return true;
        }
    }
    return false;
}

/**
 * Retrieves the mime type embedded inside the original content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 * @return String8
 *     Returns mime-type of the original content, such as "video/mpeg"
 */
String8 WVMDrmPlugin::onGetOriginalMimeType(int uniqueId, const String8& path, int fd) {
    //ALOGD("WVMDrmPlugin::onGetOriginalMimeType() : %d", uniqueId);
    return String8("video/wvm");
}

/**
 * Retrieves the type of the protected object (content, rights, etc..)
 * using specified path or mimetype. At least one parameter should be non null
 * to retrieve DRM object type
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the content or null.
 * @param[in] mimeType Mime type of the content or null.
 * @return type of the DRM content,
 *     such as DrmObjectType::CONTENT, DrmObjectType::RIGHTS_OBJECT
 */
int WVMDrmPlugin::onGetDrmObjectType(
            int uniqueId, const String8& path, const String8& mimeType) {
    //ALOGD("WVMDrmPlugin::onGetDrmObjectType() : %d", uniqueId);
    return DrmObjectType::UNKNOWN;
}

/**
 * Check whether the given content has valid rights or not
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 * @param[in] action Action to perform (Action::DEFAULT, Action::PLAY, etc)
 * @return the status of the rights for the protected content,
 *     such as RightsStatus::RIGHTS_VALID, RightsStatus::RIGHTS_EXPIRED, etc.
 */
int WVMDrmPlugin::onCheckRightsStatus(int uniqueId, const String8& path, int action) {
    //ALOGD("WVMDrmPlugin::onCheckRightsStatus() : %d", uniqueId);

    if ( (Action::DEFAULT != action) && (Action::PLAY != action) ) {
        ALOGE("onCheckRightsStatus : action %d not supported", action);
        return RightsStatus::RIGHTS_INVALID;
    }

    std::string assetPath(path.string());
    int rightsStatus = mDrmPluginImpl->CheckRightsStatus(assetPath);

    switch(rightsStatus) {
    case WVDRMPluginAPI::RIGHTS_INVALID:
        return RightsStatus::RIGHTS_INVALID;
        break;
    case WVDRMPluginAPI::RIGHTS_EXPIRED:
        return RightsStatus::RIGHTS_EXPIRED;
        break;
    case WVDRMPluginAPI::RIGHTS_VALID:
        return RightsStatus::RIGHTS_VALID;
        break;
    case WVDRMPluginAPI::RIGHTS_NOT_ACQUIRED:
        return RightsStatus::RIGHTS_NOT_ACQUIRED;
        break;
    }
    return RightsStatus::RIGHTS_INVALID;
}

/**
 * Consumes the rights for a content.
 * If the reserve parameter is true the rights is reserved until the same
 * application calls this api again with the reserve parameter set to false.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the decryption session
 * @param[in] action Action to perform. (Action::DEFAULT, Action::PLAY, etc)
 * @param[in] reserve True if the rights should be reserved.
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onConsumeRights(int uniqueId, DecryptHandle* decryptHandle,
            int action, bool reserve) {
    //ALOGD("WVMDrmPlugin::onConsumeRights() : %d", uniqueId);
    return DRM_NO_ERROR;
}

/**
 * Informs the DRM Engine about the playback actions performed on the DRM files.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the decryption session
 * @param[in] playbackStatus Playback action (Playback::START, Playback::STOP, Playback::PAUSE)
 * @param[in] position Position in the file (in milliseconds) where the start occurs.
 *     Only valid together with Playback::START.
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onSetPlaybackStatus(int uniqueId, DecryptHandle* decryptHandle,
            int playbackStatus, off64_t position) {
    //ALOGD("WVMDrmPlugin::onSetPlaybackStatus");

    int op;

    switch(playbackStatus) {
    case Playback::START:
        op = WVDRMPluginAPI::PLAYBACK_START;
        break;
    case Playback::STOP:
        op = WVDRMPluginAPI::PLAYBACK_STOP;
        break;
    case Playback::PAUSE:
        op = WVDRMPluginAPI::PLAYBACK_PAUSE;
        break;
    default:
        op = WVDRMPluginAPI::PLAYBACK_INVALID;
        break;
    }

    if (mDrmPluginImpl->SetPlaybackStatus(op, position))
        return DRM_NO_ERROR;

    return DRM_ERROR_UNKNOWN;
}

/**
 * Validates whether an action on the DRM content is allowed or not.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 * @param[in] action Action to validate (Action::PLAY, Action::TRANSFER, etc)
 * @param[in] description Detailed description of the action
 * @return true if the action is allowed.
 */
bool WVMDrmPlugin::onValidateAction(int uniqueId, const String8& path,
            int action, const ActionDescription& description) {
    //ALOGD("WVMDrmPlugin::onValidateAction() : %d", uniqueId);
    return true;
}

/**
 * Removes the rights associated with the given protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] path Path of the protected content
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onRemoveRights(int uniqueId, const String8& path) {
    //ALOGD("WVMDrmPlugin::onRemoveRights() : %d", uniqueId);

    std::string assetPath(path.string());
    if (mDrmPluginImpl->RemoveRights(assetPath))
        return DRM_NO_ERROR;

    return DRM_ERROR_UNKNOWN;
}

/**
 * Removes all the rights information of each plug-in associated with
 * DRM framework. Will be used in master reset
 *
 * @param[in] uniqueId Unique identifier for a session
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onRemoveAllRights(int uniqueId) {
    //ALOGD("WVMDrmPlugin::onRemoveAllRights() : %d", uniqueId);

    if (mDrmPluginImpl->RemoveAllRights())
        return DRM_NO_ERROR;

    return DRM_ERROR_UNKNOWN;
}

/**
 * Open the decrypt session to decrypt the given protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the current decryption session
 * @param[in] fd File descriptor of the protected content to be decrypted
 * @param[in] offset Start position of the content
 * @param[in] length The length of the protected content
 * @param[in] mime Mime type of the protected content.
 * @return
 *     DRM_ERROR_CANNOT_HANDLE for failure and DRM_NO_ERROR for success
 */
status_t WVMDrmPlugin::onOpenDecryptSession(
        int uniqueId, DecryptHandle *decryptHandle,
        int fd, off64_t offset, off64_t length, const char* mime)
{
    ALOGV("onOpenDecryptSession: id=%d,fd=%d", uniqueId, fd);

    if (!isSupportedMimeType(mime)) {
        return DRM_ERROR_CANNOT_HANDLE;
    }

    // For efficiency, we rely on the WVMExtractor's sniff result instead of
    // setting mimeType and decryptApiType here for the DRMExtractor's sniff.
    // WVMExtractor's sniff uses the cached data source for the sniff.
    decryptHandle->decryptInfo = NULL;
    decryptHandle->status = DRM_NO_ERROR;

    if (mDrmPluginImpl->OpenSession(NULL)) {
        return DRM_NO_ERROR;
    }
    return DRM_ERROR_CANNOT_HANDLE;
}

bool WVMDrmPlugin::isSupportedMimeType(const char* mime) {
    ALOGV("isSupportedMimeType: mime = %s", mime? mime: "NULL");
    return strcasecmp("video/wvm", mime) == 0;
}
/**
 * Open the decrypt session to decrypt the given protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the current decryption session
 * @param[in] uri Path of the protected content to be decrypted
 * @param[in] mime Mime type of the protected content
 * @return
 *     DRM_ERROR_CANNOT_HANDLE for failure and DRM_NO_ERROR for success
 */
status_t WVMDrmPlugin::onOpenDecryptSession(
        int uniqueId, DecryptHandle* decryptHandle,
        const char* uri, const char* mime)
{
    ALOGV("onOpenDecryptSession: id=%d,uri=%s",uniqueId,uri);
    if (!isSupportedMimeType(mime)) {
        return DRM_ERROR_CANNOT_HANDLE;
    }

    // For efficiency, we rely on the WVMExtractor's sniff result instead of
    // setting mimeType and decryptApiType here for the DRMExtractor's sniff.
    // WVMExtractor's sniff uses the cached data source for the sniff.
    status_t result = DRM_ERROR_CANNOT_HANDLE;

    if (!uri)
        return result;

    decryptHandle->decryptInfo = NULL;
    decryptHandle->status = DRM_NO_ERROR;

    if (mDrmPluginImpl->OpenSession(uri)) {
        result = DRM_NO_ERROR;
    } else {
        //ALOGD("WVMDrmPlugin::onOpenDecryptSession(uri) - not Widevine media");
    }

    return result;
}


/**
 * Close the decrypt session for the given handle
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the decryption session
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onCloseDecryptSession(int uniqueId, DecryptHandle* decryptHandle) {
    //ALOGD("WVMDrmPlugin::onCloseDecryptSession() : %d", uniqueId);
    if (NULL != decryptHandle) {
        if (NULL != decryptHandle->decryptInfo) {
            delete decryptHandle->decryptInfo; decryptHandle->decryptInfo = NULL;
        }
        delete decryptHandle; decryptHandle = NULL;
    }
    mDrmPluginImpl->CloseSession();

    return DRM_NO_ERROR;
}

/**
 * Initialize decryption for the given unit of the protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptId Handle for the decryption session
 * @param[in] decryptUnitId ID Specifies decryption unit, such as track ID
 * @param[in] headerInfo Information for initializing decryption of this decrypUnit
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onInitializeDecryptUnit(int uniqueId, DecryptHandle* decryptHandle,
            int decryptUnitId, const DrmBuffer* headerInfo) {
    //ALOGD("WVMDrmPlugin::onInitializeDecryptUnit(): %d", uniqueId);
    if (!mDrmPluginImpl->Prepare(headerInfo->data, headerInfo->length))
        return DRM_ERROR_CANNOT_HANDLE;

    return DRM_NO_ERROR;
}

/**
 * Decrypt the protected content buffers for the given unit
 * This method will be called any number of times, based on number of
 * encrypted streams received from application.
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptId Handle for the decryption session
 * @param[in] decryptUnitId ID Specifies decryption unit, such as track ID
 * @param[in] encBuffer Encrypted data block
 * @param[out] decBuffer Decrypted data block
 * @param[in] IV Optional buffer
 * @return status_t
 *     Returns the error code for this API
 *     DRM_NO_ERROR for success, and one of DRM_ERROR_UNKNOWN, DRM_ERROR_LICENSE_EXPIRED
 *     DRM_ERROR_SESSION_NOT_OPENED, DRM_ERROR_DECRYPT_UNIT_NOT_INITIALIZED,
 *     DRM_ERROR_DECRYPT for failure.
 */
status_t WVMDrmPlugin::onDecrypt(int uniqueId, DecryptHandle* decryptHandle, int decryptUnitId,
                                 const DrmBuffer* encBuffer, DrmBuffer** decBuffer,
                                 DrmBuffer *ivBuffer)
{
    //ALOGD("WVMDrmPlugin::onDecrypt\n");
#define AES_BLOCK_SIZE 16
    char iv[AES_BLOCK_SIZE];
    memcpy(iv, ivBuffer->data, sizeof(iv));

    if (*decBuffer == NULL)
        return DRM_ERROR_DECRYPT;

    int status;
    status = mDrmPluginImpl->Operate(encBuffer->data, encBuffer->length, (*decBuffer)->data, (*decBuffer)->length, iv);
    if (status != WVDRMPluginAPI::RIGHTS_VALID) {
        (*decBuffer)->length = 0;
        usleep(1000);  // prevent spinning
        if (status == WVDRMPluginAPI::RIGHTS_NOT_ACQUIRED) {
            return DRM_ERROR_NO_LICENSE;
        } else if (status == WVDRMPluginAPI::RIGHTS_EXPIRED) {
            return DRM_ERROR_LICENSE_EXPIRED;
        } else if (status == WVDRMPluginAPI::RIGHTS_INVALID) {
            return DRM_ERROR_DECRYPT;
        }
    }

    return DRM_NO_ERROR;
}

/**
 * Finalize decryption for the given unit of the protected content
 *
 * @param[in] uniqueId Unique identifier for a session
 * @param[in] decryptHandle Handle for the decryption session
 * @param[in] decryptUnitId ID Specifies decryption unit, such as track ID
 * @return status_t
 *     Returns DRM_NO_ERROR for success, DRM_ERROR_UNKNOWN for failure
 */
status_t WVMDrmPlugin::onFinalizeDecryptUnit(
            int uniqueId, DecryptHandle* decryptHandle, int decryptUnitId) {
    //ALOGD("WVMDrmPlugin::onFinalizeDecryptUnit() : %d", uniqueId);
    return DRM_NO_ERROR;
}

/**
 * The following methods are not required for the Widevine DRM plugin
 */
ssize_t WVMDrmPlugin::onPread(int uniqueId, DecryptHandle* decryptHandle,
            void* buffer, ssize_t numBytes, off64_t offset) {
    return DRM_ERROR_UNKNOWN;
}


status_t WVMDrmPlugin::onOpenConvertSession(int uniqueId, int convertId) {
    return DRM_ERROR_UNKNOWN;
}

DrmConvertedStatus* WVMDrmPlugin::onConvertData(
            int uniqueId, int convertId, const DrmBuffer* inputData) {
    return NULL;
}

DrmConvertedStatus* WVMDrmPlugin::onCloseConvertSession(int uniqueId, int convertId) {
    return NULL;
}
