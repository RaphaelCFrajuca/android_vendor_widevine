//
// Copyright 2013 Google Inc. All Rights Reserved.
//

#ifndef WV_DRM_PLUGIN_H_
#define WV_DRM_PLUGIN_H_

#include <stdint.h>
#include <map>

#include "cdm_client_property_set.h"
#include "media/drm/DrmAPI.h"
#include "media/stagefright/foundation/ABase.h"
#include "media/stagefright/foundation/AString.h"
#include "OEMCryptoCENC.h"
#include "utils/Errors.h"
#include "utils/KeyedVector.h"
#include "utils/List.h"
#include "utils/String8.h"
#include "utils/Vector.h"
#include "wv_cdm_event_listener.h"
#include "wv_content_decryption_module.h"
#include "WVGenericCryptoInterface.h"

namespace wvdrm {

using android::KeyedVector;
using android::List;
using android::status_t;
using android::String8;
using android::Vector;
using std::map;
using wvcdm::CdmEventType;
using wvcdm::CdmSessionId;
using wvcdm::CdmResponseType;
using wvcdm::WvContentDecryptionModule;

const OEMCrypto_Algorithm kInvalidCrytpoAlgorithm =
    static_cast<OEMCrypto_Algorithm>(-1);

class WVDrmPlugin : public android::DrmPlugin,
                    public wvcdm::WvCdmEventListener {
 public:
  WVDrmPlugin(WvContentDecryptionModule* cdm,
              WVGenericCryptoInterface* crypto);

  virtual ~WVDrmPlugin();

  virtual status_t openSession(Vector<uint8_t>& sessionId);

  virtual status_t closeSession(const Vector<uint8_t>& sessionId);

  virtual status_t getKeyRequest(
      const Vector<uint8_t>& scope,
      const Vector<uint8_t>& initData,
      const String8& mimeType,
      KeyType keyType,
      const KeyedVector<String8, String8>& optionalParameters,
      Vector<uint8_t>& request,
      String8& defaultUrl);

  virtual status_t provideKeyResponse(const Vector<uint8_t>& scope,
                                      const Vector<uint8_t>& response,
                                      Vector<uint8_t>& keySetId);

  virtual status_t removeKeys(const Vector<uint8_t>& sessionId);

  virtual status_t restoreKeys(const Vector<uint8_t>& sessionId,
                               const Vector<uint8_t>& keySetId);

  virtual status_t queryKeyStatus(
      const Vector<uint8_t>& sessionId,
      KeyedVector<String8, String8>& infoMap) const;

  virtual status_t getProvisionRequest(Vector<uint8_t>& request,
                                       String8& defaultUrl);

  virtual status_t provideProvisionResponse(const Vector<uint8_t>& response);

  virtual status_t getSecureStops(List<Vector<uint8_t> >& secureStops);

  virtual status_t releaseSecureStops(const Vector<uint8_t>& ssRelease);

  virtual status_t getPropertyString(const String8& name, String8& value) const;

  virtual status_t getPropertyByteArray(const String8& name,
                                        Vector<uint8_t>& value) const;

  virtual status_t setPropertyString(const String8& name, const String8& value);

  virtual status_t setPropertyByteArray(const String8& name,
                                        const Vector<uint8_t>& value);

  virtual status_t setCipherAlgorithm(const Vector<uint8_t>& sessionId,
                                      const String8& algorithm);

  virtual status_t setMacAlgorithm(const Vector<uint8_t>& sessionId,
                                   const String8& algorithm);

  virtual status_t encrypt(const Vector<uint8_t>& sessionId,
                           const Vector<uint8_t>& keyId,
                           const Vector<uint8_t>& input,
                           const Vector<uint8_t>& iv,
                           Vector<uint8_t>& output);

  virtual status_t decrypt(const Vector<uint8_t>& sessionId,
                           const Vector<uint8_t>& keyId,
                           const Vector<uint8_t>& input,
                           const Vector<uint8_t>& iv,
                           Vector<uint8_t>& output);

  virtual status_t sign(const Vector<uint8_t>& sessionId,
                        const Vector<uint8_t>& keyId,
                        const Vector<uint8_t>& message,
                        Vector<uint8_t>& signature);

  virtual status_t verify(const Vector<uint8_t>& sessionId,
                          const Vector<uint8_t>& keyId,
                          const Vector<uint8_t>& message,
                          const Vector<uint8_t>& signature,
                          bool& match);

  virtual void onEvent(const CdmSessionId& cdmSessionId,
                       CdmEventType cdmEventType);

 private:
  DISALLOW_EVIL_CONSTRUCTORS(WVDrmPlugin);

  struct CryptoSession {
   public:
    CryptoSession()
      : mOecSessionId(-1),
        mCipherAlgorithm(kInvalidCrytpoAlgorithm),
        mMacAlgorithm(kInvalidCrytpoAlgorithm) {}

    CryptoSession(OEMCrypto_SESSION sessionId)
      : mOecSessionId(sessionId),
        mCipherAlgorithm(kInvalidCrytpoAlgorithm),
        mMacAlgorithm(kInvalidCrytpoAlgorithm) {}

    OEMCrypto_SESSION oecSessionId() const { return mOecSessionId; }

    OEMCrypto_Algorithm cipherAlgorithm() const { return mCipherAlgorithm; }

    void setCipherAlgorithm(OEMCrypto_Algorithm newAlgorithm) {
      mCipherAlgorithm = newAlgorithm;
    }

    OEMCrypto_Algorithm macAlgorithm() const { return mMacAlgorithm; }

    void setMacAlgorithm(OEMCrypto_Algorithm newAlgorithm) {
      mMacAlgorithm = newAlgorithm;
    }

   private:
    OEMCrypto_SESSION mOecSessionId;
    OEMCrypto_Algorithm mCipherAlgorithm;
    OEMCrypto_Algorithm mMacAlgorithm;
  };

  class WVClientPropertySet : public wvcdm::CdmClientPropertySet {
   public:
    WVClientPropertySet()
      : mUsePrivacyMode(false), mShareKeys(false), mSessionSharingId(0) {}

    virtual ~WVClientPropertySet() {}

    virtual std::string security_level() const {
      return mSecurityLevel;
    }

    void set_security_level(const std::string& securityLevel) {
      mSecurityLevel = securityLevel;
    }

    virtual bool use_privacy_mode() const {
      return mUsePrivacyMode;
    }

    void set_use_privacy_mode(bool usePrivacyMode) {
      mUsePrivacyMode = usePrivacyMode;
    }

    virtual std::vector<uint8_t> service_certificate() const {
      return mServiceCertificate;
    }

    void set_service_certificate(const std::vector<uint8_t>& serviceCertificate) {
      mServiceCertificate = serviceCertificate;
    }

    virtual bool is_session_sharing_enabled() const {
      return mShareKeys;
    }

    void set_is_session_sharing_enabled(bool shareKeys) {
      mShareKeys = shareKeys;
    }

    virtual uint32_t session_sharing_id() const {
      return mSessionSharingId;
    }

    virtual void set_session_sharing_id(uint32_t id) {
      mSessionSharingId = id;
    }

   private:
    DISALLOW_EVIL_CONSTRUCTORS(WVClientPropertySet);

    std::string mSecurityLevel;
    bool mUsePrivacyMode;
    std::vector<uint8_t> mServiceCertificate;
    bool mShareKeys;
    uint32_t mSessionSharingId;
  } mPropertySet;

  WvContentDecryptionModule* mCDM;
  WVGenericCryptoInterface* mCrypto;
  map<CdmSessionId, CryptoSession> mCryptoSessions;

  status_t mapAndNotifyOfCdmResponseType(const Vector<uint8_t>& sessionId,
                                         CdmResponseType res);

  status_t mapAndNotifyOfOEMCryptoResult(const Vector<uint8_t>& sessionId,
                                         OEMCryptoResult res);
};

} // namespace wvdrm

#endif // WV_DRM_PLUGIN_H_
