/*********************************************************************
 * OEMCryptoCENC.h
 *
 * (c) Copyright 2013 Google, Inc.
 *
 * Reference APIs needed to support Widevine's crypto algorithms.
 *********************************************************************/

#ifndef OEMCRYPTO_CENC_H_
#define OEMCRYPTO_CENC_H_

#include<stddef.h>
#include<stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OEMCRYPTO_VERSION "8.0"
static const char oec_version[] = OEMCRYPTO_VERSION;
static const uint32_t oec_latest_version = 8;

typedef uint32_t OEMCrypto_SESSION;

typedef enum OEMCryptoResult {
    OEMCrypto_SUCCESS                            = 0,
    OEMCrypto_ERROR_INIT_FAILED                  = 1,
    OEMCrypto_ERROR_TERMINATE_FAILED             = 2,
    OEMCrypto_ERROR_OPEN_FAILURE                 = 3,
    OEMCrypto_ERROR_CLOSE_FAILURE                = 4,
    OEMCrypto_ERROR_ENTER_SECURE_PLAYBACK_FAILED = 5,
    OEMCrypto_ERROR_EXIT_SECURE_PLAYBACK_FAILED  = 6,
    OEMCrypto_ERROR_SHORT_BUFFER                 = 7,
    OEMCrypto_ERROR_NO_DEVICE_KEY                = 8,
    OEMCrypto_ERROR_NO_ASSET_KEY                 = 9,
    OEMCrypto_ERROR_KEYBOX_INVALID               = 10,
    OEMCrypto_ERROR_NO_KEYDATA                   = 11,
    OEMCrypto_ERROR_NO_CW                        = 12,
    OEMCrypto_ERROR_DECRYPT_FAILED               = 13,
    OEMCrypto_ERROR_WRITE_KEYBOX                 = 14,
    OEMCrypto_ERROR_WRAP_KEYBOX                  = 15,
    OEMCrypto_ERROR_BAD_MAGIC                    = 16,
    OEMCrypto_ERROR_BAD_CRC                      = 17,
    OEMCrypto_ERROR_NO_DEVICEID                  = 18,
    OEMCrypto_ERROR_RNG_FAILED                   = 19,
    OEMCrypto_ERROR_RNG_NOT_SUPPORTED            = 20,
    OEMCrypto_ERROR_SETUP                        = 21,
    OEMCrypto_ERROR_OPEN_SESSION_FAILED          = 22,
    OEMCrypto_ERROR_CLOSE_SESSION_FAILED         = 23,
    OEMCrypto_ERROR_INVALID_SESSION              = 24,
    OEMCrypto_ERROR_NOT_IMPLEMENTED              = 25,
    OEMCrypto_ERROR_NO_CONTENT_KEY               = 26,
    OEMCrypto_ERROR_CONTROL_INVALID              = 27,
    OEMCrypto_ERROR_UNKNOWN_FAILURE              = 28,
    OEMCrypto_ERROR_INVALID_CONTEXT              = 29,
    OEMCrypto_ERROR_SIGNATURE_FAILURE            = 30,
    OEMCrypto_ERROR_TOO_MANY_SESSIONS            = 31,
    OEMCrypto_ERROR_INVALID_NONCE                = 32,
    OEMCrypto_ERROR_TOO_MANY_KEYS                = 33,
    OEMCrypto_ERROR_DEVICE_NOT_RSA_PROVISIONED   = 34,
    OEMCrypto_ERROR_INVALID_RSA_KEY              = 35,
    OEMCrypto_ERROR_KEY_EXPIRED                  = 36,
    OEMCrypto_ERROR_INSUFFICIENT_RESOURCES       = 37,
} OEMCryptoResult;

/*
 * OEMCrypto_DestBufferDesc
 *  Describes the type and access information for the memory to receive
 *  decrypted data.
 *
 *  The OEMCrypto API supports a range of client device architectures.
 *  Different architectures have different methods for acquiring and securing
 *  buffers that will hold portions of the audio or video stream after
 *  decryption.  Three basic strategies are recognized for handling decrypted
 *  stream data:
 *  1. Return the decrypted data in the clear into normal user memory
 *     (ClearBuffer). The caller uses normal memory allocation methods to
 *     acquire a buffer, and supplies the memory address of the buffer in the
 *     descriptor.
 *  2. Place the decrypted data into protected memory (SecureBuffer).  The
 *     caller uses a platform-specific method to acquire the protected buffer
 *     and a user-memory handle that references it.  The handle is supplied
 *     to the decrypt call in the descriptor.
 *  3. Place the decrypted data directly into the audio or video decoder fifo
 *     (Direct). The caller will use platform-specific methods to initialize
 *     the fifo and the decoders.  The decrypted stream data is not accessible
 *     to the caller.
 *
 *  Specific fields are as follows:
 *
 *  (type == OEMCrypto_BufferType_Clear)
 *      address - Address of start of user memory buffer.
 *      max_length - Size of user memory buffer.
 *  (type == OEMCrypto_BufferType_Secure)
 *      buffer - handle to a platform-specific secure buffer.
 *      max_length - Size of platform-specific secure buffer.
 *  (type == OEMCrypto_BufferType_Direct)
 *      is_video - If true, decrypted bytes are routed to the video
 *                 decoder.  If false, decrypted bytes are routed to the
 *                 audio decoder.
 */
typedef enum OEMCryptoBufferType {
    OEMCrypto_BufferType_Clear,
    OEMCrypto_BufferType_Secure,
    OEMCrypto_BufferType_Direct
} OEMCrytoBufferType;

typedef struct {
    OEMCryptoBufferType type;
    union {
        struct {                   // type == OEMCrypto_BufferType_Clear
            uint8_t* address;
            size_t max_length;
        } clear;
        struct {                   // type == OEMCrypto_BufferType_Secure
            void* handle;
            size_t max_length;
            size_t offset;
        } secure;
        struct {                   // type == OEMCrypto_BufferType_Direct
            bool is_video;
        } direct;
    } buffer;
} OEMCrypto_DestBufferDesc;

/*
 * OEMCrypto_KeyObject
 *  Points to the relevant fields for a content key.  The fields are extracted
 *  from the License Response message offered to OEMCrypto_LoadKeys().  Each
 *  field points to one of the components of the key.  Key data, key control,
 *  and both IV fields are 128 bits (16 bytes):
 *    key_id - the unique id of this key.
 *    key_id_length - the size of key_id.
 *    key_data_iv - the IV for performing AES-128-CBC decryption of the
 *        key_data field.
 *    key_data - the key data.  It is encrypted (AES-128-CBC) with the
 *        session's derived encrypt key and the key_data_iv.
 *    key_control_iv - the IV for performing AES-128-CBC decryption of the
 *        key_control field.
 *    key_control - the key control block.  It is encrypted (AES-128-CBC) with
 *        the content key from the key_data field.
 *
 *  The memory for the OEMCrypto_KeyObject fields is allocated and freed
 *  by the caller of OEMCrypto_LoadKeys().
 */
typedef struct {
    const uint8_t* key_id;
    size_t         key_id_length;
    const uint8_t* key_data_iv;
    const uint8_t* key_data;
    size_t         key_data_length;
    const uint8_t* key_control_iv;
    const uint8_t* key_control;
} OEMCrypto_KeyObject;

/*
 * OEMCrypto_KeyRefreshObject
 *  Points to the relevant fields for renewing a content key.  The fields are
 *  extracted from the License Renewal Response message offered to
 *  OEMCrypto_RefreshKeys().  Each field points to one of the components of
 *  the key.
 *    key_id - the unique id of this key.
 *    key_control_iv - the IV for performing AES-128-CBC decryption of the
 *        key_control field. 16 bytes.
 *    key_control - the key control block.  It is encrypted (AES-128-CBC) with
 *        the content key from the key_data field. 16 bytes.
 *
 *  The key_data is unchanged from the original OEMCrypto_LoadKeys() call. Some
 *  Key Control Block fields, especially those related to key lifetime, may
 *  change.
 *
 *  The memory for the OEMCrypto_KeyRefreshObject fields is allocated and freed
 *  by the caller of OEMCrypto_RefreshKeys().
 */
typedef struct {
    const uint8_t* key_id;
    size_t key_id_length;
    const uint8_t* key_control_iv;
    const uint8_t* key_control;
} OEMCrypto_KeyRefreshObject;

/*
 * OEMCrypto_Algorithm
 * This is a list of valid algorithms for OEMCrypto_Generic_* functions.
 * Some are valid for encryption/decryption, and some for signing/verifying.
 */
typedef enum OEMCrypto_Algorithm {
    OEMCrypto_AES_CBC_128_NO_PADDING = 0,
    OEMCrypto_HMAC_SHA256            = 1,
} OEMCrypto_Algorithm;

/*
 * Flags indicating data endpoints in OEMCrypto_DecryptCTR.
 */
#define OEMCrypto_FirstSubsample 1
#define OEMCrypto_LastSubsample  2

/* Obfuscation Renames. */
#define OEMCrypto_Initialize               _oecc01
#define OEMCrypto_Terminate                _oecc02
#define OEMCrypto_InstallKeybox            _oecc03
#define OEMCrypto_GetKeyData               _oecc04
#define OEMCrypto_IsKeyboxValid            _oecc05
#define OEMCrypto_GetRandom                _oecc06
#define OEMCrypto_GetDeviceID              _oecc07
#define OEMCrypto_WrapKeybox               _oecc08
#define OEMCrypto_OpenSession              _oecc09
#define OEMCrypto_CloseSession             _oecc10
#define OEMCrypto_DecryptCTR               _oecc11
#define OEMCrypto_GenerateDerivedKeys      _oecc12
#define OEMCrypto_GenerateSignature        _oecc13
#define OEMCrypto_GenerateNonce            _oecc14
#define OEMCrypto_LoadKeys                 _oecc15
#define OEMCrypto_RefreshKeys              _oecc16
#define OEMCrypto_SelectKey                _oecc17
#define OEMCrypto_RewrapDeviceRSAKey       _oecc18
#define OEMCrypto_LoadDeviceRSAKey         _oecc19
#define OEMCrypto_GenerateRSASignature     _oecc20
#define OEMCrypto_DeriveKeysFromSessionKey _oecc21
#define OEMCrypto_APIVersion               _oecc22
#define OEMCrypto_SecurityLevel            _oecc23
#define OEMCrypto_Generic_Encrypt          _oecc24
#define OEMCrypto_Generic_Decrypt          _oecc25
#define OEMCrypto_Generic_Sign             _oecc26
#define OEMCrypto_Generic_Verify           _oecc27

/*
 * OEMCrypto_Initialize
 *
 * Description:
 *   Initialize the crypto firmware/hardware.
 *
 * Parameters:
 *   N/A
 *
 * Threading:
 *   No other function calls will be made while this function is running. This
 *   function will not be called again before OEMCrypto_Terminate.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INIT_FAILED failed to initialize crypto hardware
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_Initialize(void);

/*
 * OEMCrypto_Terminate
 *
 * Description:
 *   The API closes the crypto operation and releases all resources used.
 *
 * Parameters:
 *   N/A
 *
 * Threading:
 *   No other OEMCrypto calls are made while this function is running.  After
 *   this function is called, no other OEMCrypto calls will be made until another
 *   call to OEMCrypto_Initialize is made.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_TERMINATE_FAILED failed to de-initialize crypto hardware
 *
 * Version:
 *   This method is all API versions.
 */
OEMCryptoResult OEMCrypto_Terminate(void);

/*
 * OEMCrypto_OpenSession
 *
 * Description:
 *   The API provides for session based crypto initialization for AES CTR mode.
 *
 * Parameters:
 *   session (out) - pointer to crypto session identifier.
 *
 * Threading:
 *   No other Open/Close session calls will be made while this function is
 *   running. Functions on existing sessions may be called while this function
 *   is active.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_TOO_MANY_SESSIONS failed because too many sessions are open
 *   OEMCrypto_ERROR_OPEN_SESSION_FAILED failed to initialize the crypto session
 *
 * Version:
 *   This method changed in API version 5.
 */
OEMCryptoResult OEMCrypto_OpenSession(OEMCrypto_SESSION *session);

/*
 * OEMCrypto_CloseSession
 *
 * Description:
 *   The API provides for session based crypto termination for AES CTR mode.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *
 * Threading:
 *   No other Open/Close session calls will be made while this function is
 *   running. Functions on existing sessions may be called while this function
 *   is active.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INVALID_SESSION no open session with that id.
 *   OEMCrypto_ERROR_CLOSE_SESSION_FAILED failed to terminate the crypto session
 *
 * Version:
 *   This method changed in API version 5.
 */
OEMCryptoResult OEMCrypto_CloseSession(OEMCrypto_SESSION session);

/*
 * OEMCrypto_GenerateDerivedKeys
 *
 * Description:
 *   Generates three secondary keys -- mac_key_server, mac_key_client, and
 *   encrypt_key -- for handling signing and content key decryption under the
 *   license server protocol for AES CTR mode.
 *
 *   Refer to document "Widevine Modular DRM Security Integration Guide for
 *   CENC" for details.  This function computes the AES-128-CMAC of the
 *   enc_key_context and stores it in secure memory as the encrypt_key.  It
 *   then computes four cycles of AES-128-CMAC of the mac_key_context and
 *   stores it in the mac_keys.  The first two cycles are used for
 *   mac_key_server and the second two cycles are used for mac_key_client.
 *   These three keys will be stored until the next call to LoadKeys.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   mac_key_context (in) - pointer to memory containing context data for
 *                          computing the HMAC generation key.
 *   mac_key_context_length (in) - length of the HMAC key context data.
 *   enc_key_context (in) - pointer to memory containing context data for
 *                          computing the encryption key.
 *   enc_key_context_length (in) - length of the encryption key context data.
 *
 * Results:
 *  mac_key_server: the 256 bit mac key is generated and stored in secure memory.
 *  mac_key_client: the 256 bit mac key is generated and stored in secure memory.
 *  enc_key: the 128 bit encryption key is generated and stored in secure memory.
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 8.
 */
OEMCryptoResult OEMCrypto_GenerateDerivedKeys(
                            OEMCrypto_SESSION session,
                            const uint8_t *mac_key_context,
                            uint32_t mac_key_context_length,
                            const uint8_t *enc_key_context,
                            uint32_t enc_key_context_length);

/*
 * OEMCrypto_GenerateNonce
 *
 * Description:
 *   Generates a 32-bit nonce to detect possible replay attack on the key
 *   control block.  The nonce is stored in secure memory and will be used
 *   for the next call to LoadKeys.
 *
 *   Refer to documents "Widevine Modular DRM Security Integration Guide for
 *   CENC".
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   nonce (out) - pointer to memory to received the computed nonce.
 *
 * Results:
 *  nonce: the nonce is also stored in secure memory.
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 5.
 */
OEMCryptoResult OEMCrypto_GenerateNonce(
                            OEMCrypto_SESSION session,
                            uint32_t* nonce);

/*
 * OEMCrypto_GenerateSignature
 *
 * Description:
 *   Generates a HMAC-SHA256 signature for license request signing under the
 *   license server protocol for AES CTR mode. This uses the key mac_key_client.
 *
 *   NOTE: OEMCrypto_GenerateDerivedKeys() must be called first to establish the
 *       mac_key_client.
 *
 *   Refer to document "Widevine Modular DRM Security Integration Guide for
 *   CENC" for details.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   message (in) - pointer to memory containing message to be signed.
 *   message_length (in) - length of the message.
 *   signature (out) - pointer to memory to received the computed signature.
 *   signature_length (in/out) - (in) length of the signature buffer.
 *                               (out) actual length of the signature
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_SHORT_BUFFER
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 5.
 */
OEMCryptoResult OEMCrypto_GenerateSignature(
                            OEMCrypto_SESSION session,
                            const uint8_t* message,
                            size_t message_length,
                            uint8_t* signature,
                            size_t* signature_length);

/*
 * OEMCrypto_LoadKeys
 *
 * Description:
 *   Installs a set of keys for performing decryption in the current session.
 *
 *   The relevant fields have been extracted from the License Response protocol
 *   message, but the entire message and associated signature are provided so
 *   the message can be verified (using HMAC-SHA256 with the derived
 *   mac_key_server). If the signature verification fails, ignore all other
 *   arguments and return OEMCrypto_ERROR_SIGNATURE_FAILURE.  Otherwise, add the
 *   keys to the session context.
 *
 *   The keys will be decrypted using the current encrypt_key (AES-128-CBC) and
 *   the IV given in the KeyObject.  Each key control block will be decrypted
 *   using the corresponding content key (AES-128-CBC) and the IV given in the
 *   KeyObject.
 *
 *   If any key's control block does not have valid verification fields, return
 *   OEMCrypto_ERROR_INVALID_CONTEXT and do not install any keys.
 *
 *   If any key's control block requires a nonce, and the nonce in the control
 *   block is different from the current nonce, return
 *   OEMCrypto_ERROR_INVALID_NONCE.  In that case, do not install any keys.
 *
 *   The new mac_keys are decrypted with the current encrypt_key and the offered
 *   IV.  They replace the current mac_keys.
 *
 *   The mac_keys and encrypt_key were generated and stored by the previous call
 *   to OEMCrypto_GenerateDerivedKeys().  The nonce was generated and stored by
 *   the previous call to OEMCrypto_GenerateNonce().
 *
 *   This session’s elapsed time clock is started at 0.  The clock will be used
 *   in OEMCrypto_DecryptCTR.
 *
 *   NOTE: OEMCrypto_GenerateDerivedKeys() must be called first to establish
 *       the mac_keys and encrypt_key.
 *
 *   Refer to document "Widevine Modular DRM Security Integration Guide for
 *   CENC" for details.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   message (in) - pointer to memory containing message to be verified.
 *   message_length (in) - length of the message.
 *   signature (in) - pointer to memory containing the signature.
 *   signature_length (in) - length of the signature.
 *   enc_mac_keys_iv (in) - IV for decrypting new mac_key.  Size is 128 bits.
 *   enc_mac_keys (in) - encrypted mac_keys for generating new mac_keys. Size is
 *                       512 bits.
 *   num_keys (in) - number of keys present.
 *   key_array (in) - set of keys to be installed.
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_SIGNATURE_FAILURE
 *   OEMCrypto_ERROR_INVALID_NONCE
 *   OEMCrypto_ERROR_TOO_MANY_KEYS
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 8.
 */
OEMCryptoResult OEMCrypto_LoadKeys(OEMCrypto_SESSION session,
                                   const uint8_t* message,
                                   size_t message_length,
                                   const uint8_t* signature,
                                   size_t signature_length,
                                   const uint8_t* enc_mac_keys_iv,
                                   const uint8_t* enc_mac_keys,
                                   size_t num_keys,
                                   const OEMCrypto_KeyObject* key_array);

/*
 * OEMCrypto_RefreshKeys
 *
 * Description:
 *   Updates an existing set of keys for continuing decryption in the
 *   current session.
 *
 *   The relevant fields have been extracted from the Renewal Response protocol
 *   message, but the entire message and associated signature are provided so
 *   the message can be verified (using HMAC-SHA256 with the current
 *   mac_key_server).  If the signature verification fails, ignore all other
 *   arguments and return OEMCrypto_ERROR_SIGNATURE_FAILURE.  Otherwise, add
 *   the keys to the session context.
 *
 *   NOTE: OEMCrypto_GenerateDerivedKeys() or OEMCrypto_LoadKeys() must be
 *   called first to establish the mac_keys.
 *
 *   Refer to document "Widevine Modular DRM Security Integration Guide for
 *   CENC" for details.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   message (in) - pointer to memory containing message to be verified.
 *   message_length (in) - length of the message.
 *   signature (in) - pointer to memory containing the signature.
 *   signature_length (in) - length of the signature.
 *   num_keys (in) - number of keys present.
 *   key_array (in) - set of keys to be installed.
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_INVALID_NONCE
 *   OEMCrypto_ERROR_SIGNATURE_FAILURE
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 8.
 */
OEMCryptoResult
OEMCrypto_RefreshKeys(OEMCrypto_SESSION session,
                      const uint8_t* message,
                      size_t message_length,
                      const uint8_t* signature,
                      size_t signature_length,
                      size_t num_keys,
                      const OEMCrypto_KeyRefreshObject* key_array);

/*
 * OEMCrypto_SelectKey
 *
 * Description:
 *   Select a content key and install it in the hardware key ladder for
 *   subsequent decryption operations (OEMCrypto_DecryptCTR()) for this session.
 *   The specified key must have been previously "installed" via
 *   OEMCrypto_LoadKeys() or OEMCrypto_RefreshKeys().
 *
 *   This session’s elapsed time clock is started at 0.  The clock will be used
 *   in OEMCrypto_DecryptCTR.
 *
 *   A key control block is associated with the key and the session, and is used
 *   to configure the session context.  The Key Control data is documented in
 *   "Key Control Block Definition".
 *
 *   Step 1: Lookup the content key data via the offered key_id.  The key data
 *           includes the key value, the content key IV, the key control
 *           block, and the key control block IV.
 *
 *   Step 2: Latch the content key into the hardware key ladder.  Set
 *           permission flags and timers based on the key's control block.
 *
 *   Step 3: use the latched content key to decrypt (AES-128-CTR)
 *           to decrypt buffers passed in via OEMCrypto_DecryptCTR().  Continue
 *           to use this key until OEMCrypto_SelectKey() is called again, or
 *           until OEMCrypto_CloseSession() is called.
 *
 * Parameters:
 *    session (in) - crypto session identifier
 *    key_id (in) - pointer to the Key ID
 *    key_id_length (in) - length of the Key ID in bytes
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INVALID_SESSION crypto session ID invalid or not open
 *   OEMCrypto_ERROR_NO_DEVICE_KEY failed to decrypt device key
 *   OEMCrypto_ERROR_NO_CONTENT_KEY failed to decrypt content key
 *   OEMCrypto_ERROR_CONTROL_INVALID invalid or unsupported control input
 *   OEMCrypto_ERROR_KEYBOX_INVALID cannot decrypt and read from Keybox
 *   OEMCrypto_ERROR_KEY_EXPIRED
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 8.
 */
OEMCryptoResult OEMCrypto_SelectKey(const OEMCrypto_SESSION session,
                                    const uint8_t* key_id,
                                    size_t key_id_length);

/*
 * OEMCrypto_DecryptCTR
 *
 * Description:
 *
 * The API decrypts (AES-CTR) or copies the payload in the buffer referenced by
 * the data_addr parameter to the buffer determined by out_buffer, using the key
 * previously set by a call to OEMCrypto_SelectKey for the specified session.
 *
 * Parameters:
 *   session (in) - crypto session identifier.
 *   data_addr (in) -  An unaligned pointer to this segment of the stream.
 *   data_length (in) -  The length of this segment of the stream.
 *   is_encrypted (in) -  True if the buffer described by data_addr,
 *       data_length is encrypted.  If is_encrypted is false, only the
 *       data_addr and data_length parameters are used. The iv and offset
 *       arguments are ignored.
 *   iv (in) -  The initial value block to be used for content decryption.
 *       This is discussed further below.
 *   block_offset (in) -  If non-zero, the decryption block boundary is
 *       different from the start of the data. offset should be subtracted from
 *       data_addr to compute the starting address of the first decrypted
 *       block. The bytes between the decryption block start address and
 *       data_addr are discarded after decryption.  This is only used to adjust
 *       the start of decryption block.  It does not adjust the beginning of the
 *       source or destination data.  0 <= block_offset < 16.
 *   out_buffer (in) -  A caller-owned descriptor that specifies the
 *       handling of the decrypted byte stream. See OEMCrypto_DestbufferDesc
 *       for details.
 *   subsample_flags (in) -  bitwise flags indicating if this is the first,
 *       middle, or last subsample in a chunk of data. 1 = first subsample,
 *       2 = last subsample, 3 = both first and last subsample, 0 = neither
 *       first nor last subsample.
 *
 *   AES CTR is a stream cipher. The stream may be composed of arbitrary-
 *   length clear and encrypted segments. The encrypted portions of a sample
 *   are collectively treated as a continuous sequence of decryption
 *   block-sized blocks even though the sequence is interrupted by clear blocks.
 *   This means a given encrypted segment may not start or end on a decryption
 *   block boundary.
 *
 *   If data_addr is not aligned with a decryption block boundary (offset != 0),
 *   the additional offset bytes before data_addr (pre-padding) are included in
 *   the decrypt operation, and they are dropped after decryption.  If
 *   data_length + offset is not a multiple of the decryption block size, the
 *   extra bytes in the final decryption block (post-padding) are also dropped
 *   after decryption.  The caller is responsible for guaranteeing that all
 *   memory addresses from (data-addr - pre-padding) to (data-addr +
 *   data-length + post-padding) are valid memory addresses.
 *
 *   After decrypting the entire buffer including any pre-padding and
 *   post-padding, send data_length bytes starting at data_addr to the decoder.
 *
 * NOTES:
 *   IV points to the counter value to be used for the initial
 *   encrypted block of the input buffer. The IV length is the AES
 *   block size. For subsequent encrypted AES blocks the IV is
 *   calculated by incrementing the lower 64 bits (byte 8-15) of the
 *   IV value used for the previous block. The counter rolls over to
 *   zero when it reaches its maximum value (0xFFFFFFFFFFFFFFFF).
 *   The upper 64 bits (byte 0-7) of the IV do not change.
 *
 *   This method may be called several times before the decrypted data is used.
 *   For this reason, the parameter subsample_flags may be used to optimize
 *   decryption.  The first buffer in a chunk of data will have the
 *   OEMCrypto_FirstSubsample bit set in subsample_flags.  The last buffer in a
 *   chunk of data will have the OEMCrypto_LastSubsample bit set in
 *   subsample_flags.  The decrypted data will not be used until after
 *   OEMCrypto_LastSubsample has been set.  If an implementation decrypts data
 *   immediately, it may ignore subsample_flags.
 *
 * Threading:
 *   This function may be called simultaneously with functions on other sessions,
 *   but not with other functions on this session.
 *
 * Returns:
 *   OEMCrypto_SUCCESS
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_DECRYPT_FAILED
 *   OEMCrypto_ERROR_KEY_EXPIRED
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 5.
 */
OEMCryptoResult OEMCrypto_DecryptCTR(OEMCrypto_SESSION session,
                                     const uint8_t *data_addr,
                                     size_t data_length,
                                     bool is_encrypted,
                                     const uint8_t *iv,
                                     size_t block_offset,
                                     const OEMCrypto_DestBufferDesc* out_buffer,
                                     uint8_t subsample_flags);

/*
 * OEMCrypto_WrapKeybox
 *
 * Description:
 *   Wrap the Keybox with a key derived from the device key.  If transportKey
 *   is not NULL, the input keybox is encrypted with transportKey.  If so,
 *   decrypt the input keybox before wrapping it, using transportKey in AES-CBC
 *   mode with an IV of all zeroes.  This function is only needed if the
 *   provisioning method involves saving the keybox to the file system.
 *
 * Parameters:
 *   keybox (in) - Pointer to keybox data.
 *   keyboxLength - Length of the Keybox data in bytes
 *   wrappedKeybox (out) - Pointer to wrapped keybox
 *   wrappedKeyboxLength (out) - Pointer to the length of the wrapped keybox in
 *                               bytes
 *   transportKey (in) - An optional AES transport key. If provided, the input
 *                       keybox is encrypted with this transport key with AES-CBC
 *                       and a null IV.
 *   transportKeyLength - number of bytes in the transportKey
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_WRAP_KEYBOX failed to wrap Keybox
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_NOT_IMPLEMENTED
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_WrapKeybox(const uint8_t *keybox,
                                     size_t keyBoxLength,
                                     uint8_t *wrappedKeybox,
                                     size_t *wrappedKeyBoxLength,
                                     const uint8_t *transportKey,
                                     size_t transportKeyLength);


/*
 * OEMCrypto_InstallKeybox
 *
 * Description:
 *   Unwrap and store the keybox to persistent memory.
 *   The device key must be stored securely.
 *
 *   This function is used once to load the keybox onto the device at
 *   provisioning time.
 *
 * Parameters:
 *   keybox (in) - Pointer to clear keybox data.  Must have been originally
 *                 wrapped with OEMCrypto_WrapKeybox.
 *   keyboxLength (in) - Length of the keybox data in bytes.
 *
 * Threading:
 *   This function is not called simultaneously with any other functions.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_WRITE_KEYBOX failed to handle and store Keybox
 *
 * Version:
 *   This method is all API versions.
 */
OEMCryptoResult OEMCrypto_InstallKeybox(const uint8_t *keybox,
                                        size_t keyBoxLength);

/*
 * OEMCrypto_IsKeyboxValid
 *
 * Description:
 *   Validate the Widevine Keybox stored on the device.
 *
 * The API performs two verification steps on the Keybox. It first verifies
 * the MAGIC field contains a valid signature (must be 'kbox'). The API then
 * computes the CRC using CRC-32 (Posix 1003.2 standard) and compares the
 * checksum to the CRC stored in the Keybox. The CRC is computed over the
 * entire Keybox excluding the 4 CRC bytes (i.e. Keybox[0..123]).
 *
 * Parameters:
 *   none
 *
 * Threading:
 *   This function may be called simultaneously with any session functions.
 *
 * Returns:
 *   OEMCrypto_SUCCESS
 *   OEMCrypto_ERROR_BAD_MAGIC
 *   OEMCrypto_ERROR_BAD_CRC
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_IsKeyboxValid(void);

/*
 * OEMCrypto_GetDeviceID
 *
 * Description:
 *   Retrieve the device's unique identifier from the Keybox.
 *
 * Parameters:
 *   deviceId (out) - pointer to the buffer that receives the Device ID
 *   idLength (in/out) - on input, size of the caller's device ID buffer.
 *        On output, the number of bytes written into the buffer.
 *
 * Threading:
 *   This function may be called simultaneously with any session functions.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_SHORT_BUFFER buffer is too small to return the device ID
 *   OEMCrypto_ERROR_NO_DEVICEID failed to return Device Id
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_GetDeviceID(uint8_t* deviceID,
                                      size_t *idLength);

/*
 * OEMCrypto_GetKeyData
 *
 * Description:
 *   Returns the Key Data field from the Keybox. The Key Data field does not
 *   need to be encrypted by an OEM root key, but may be if desired.
 *
 *   If the Key Data field was encrypted with an OEM root key when the Keybox
 *   was stored on the device, then this function should decrypt it and return
 *   the clear Key Data. If the Key Data was not encrypted, then this function
 *   should just access and return the clear Key data.
 *
 * Parameters:
 *   keyData (out) - pointer to a caller-managed buffer to hold the Key Data
 *                   field from the Keybox
 *   dataLength (in/out) - on input, the allocated buffer size.  On output,
 *                   the number of bytes in KeyData.
 *
 * Threading:
 *   This function may be called simultaneously with any session functions.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_SHORT_BUFFER the buffer is too small to return the KeyData
 *   OEMCrypto_ERROR_NO_KEYDATA failed to return KeyData
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_GetKeyData(uint8_t* keyData,
                                     size_t *keyDataLength);

/*
 * OEMCrypto_GetRandom
 *
 * Description:
 *   Return a buffer filled with hardware-generated random bytes. If the
 *   hardware feature does not exist, return OEMCrypto_ERROR_RNG_NOT_SUPPORTED.
 *
 * Parameters:
 *   randomData (out) - Pointer to caller-manager buffer that will receive the
 *                      random data.
 *   dataLength (in)  - Length of the random data buffer in bytes.
 *
 * Threading:
 *   This function may be called simultaneously with any session functions.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_RNG_FAILED failed to generate random number
 *   OEMCrypto_ERROR_RNG_NOT_SUPPORTED function not supported
 *
 * Version:
 *   This method is supported by all API versions.
 */
OEMCryptoResult OEMCrypto_GetRandom(uint8_t* randomData,
                                    size_t dataLength);

/*
 * OEMCrypto_RewrapDeviceRSAKey
 *
 * Description:
 *   Verifies an RSA provisioning response is valid and corresponds
 *   to the previous provisioning request by checking the nonce.  The RSA
 *   private key is decrypted and stored in secure memory.  The RSA key is then
 *   re-encrypted for storage on the filesystem. The OEM may either encrypt it
 *   with the private key from the Widevine Keybox, or with an OEM specific
 *   device key.  The signature of the message is verified with the
 *   mac_key_server.
 *
 * Parameters:
 *   session (in)            - crypto session identifier.
 *   message (in)            - pointer to memory containing message to be
 *                           - verified.
 *   message_length (in)     - length of the message, in bytes.
 *   signature (in)          - pointer to memory containing the HMAC-SHA256
 *                           - signature for message, received from the
 *                           - provisioning server.
 *   signature_length (in)   - length of the signature, in bytes.
 *   nonce (in)              - The nonce provided in the provisioning response.
 *   enc_rsa_key (in)        - Encrypted device private RSA key received from
 *                           - the provisioning server. Format is PKCS#8
 *                           - PrivateKeyInfo, encrypted with the derived
 *                           - encryption key, using AES-128-CBC with PKCS#5
 *                           - padding.
 *   enc_rsa_key_length (in) - length of the encrypted RSA key, in bytes.
 *   enc_rsa_key_iv (in)     - IV for decrypting RSA key.  Size is 128 bits.
 *   wrapped_rsa_key (out)   - pointer to buffer in which encrypted RSA key
 *                           - should be stored.  May be null on the first call
 *                           - in order to find required buffer size.
 *   wrapped_rsa_key_length (in/out) - length of the encrypted RSA key, in bytes.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_RSA_KEY
 *   OEMCrypto_ERROR_SIGNATURE_FAILURE
 *   OEMCrypto_ERROR_INVALID_NONCE
 *   OEMCrypto_ERROR_SHORT_BUFFER
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API versions 8.
 */

OEMCryptoResult OEMCrypto_RewrapDeviceRSAKey(OEMCrypto_SESSION session,
                                             const uint8_t* message,
                                             size_t message_length,
                                             const uint8_t* signature,
                                             size_t signature_length,
                                             const uint32_t *nonce,
                                             const uint8_t* enc_rsa_key,
                                             size_t enc_rsa_key_length,
                                             const uint8_t* enc_rsa_key_iv,
                                             uint8_t* wrapped_rsa_key,
                                             size_t *wrapped_rsa_key_length);

/*
 * OEMCrypto_LoadDeviceRSAKey
 *
 * Description:
 *   Loads a wrapped RSA private key to secure memory for use by this session
 *   in future calls to OEMCrypto_GenerateRSASignature.  The wrapped RSA key
 *   will be one verified and wrapped by OEMCrypto_RewrapDeviceRSAKey.  The RSA
 *   private key should be stored in secure memory.
 *
 * Parameters:
 *   session (in)                - crypto session identifier.
 *   wrapped_rsa_key (in)        - wrapped device RSA key stored on the device.
 *                               - Format is PKCS#8 PrivateKeyInfo, and
 *                               - encrypted with a key internal to the OEMCrypto
 *                               - instance, using AES-128-CBC with PKCS#5
 *                               - padding.  This is the wrapped key generated
 *                               - by OEMCrypto_RewrapDeviceRSAKey.
 *   wrapped_rsa_key_length (in) - length of the wrapped key buffer, in bytes.
 *   wrapped_rsa_key_iv (in)     - The initialization vector used to encrypt
 *                               - wrapped_rsa_key.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_NO_DEVICE_KEY
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_RSA_KEY
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 6.
 */
OEMCryptoResult OEMCrypto_LoadDeviceRSAKey(OEMCrypto_SESSION session,
                                           const uint8_t* wrapped_rsa_key,
                                           size_t wrapped_rsa_key_length);

/*
 * OEMCrypto_GenerateRSASignature
 *
 * Description:
 *   The OEMCrypto_GenerateRSASignature method is used to sign messages using
 *   the device private RSA key, specifically, it is used to sign the initial
 *   license request.
 *
 *   Refer to the document "Widevine Security Integration Guide for DASH" for
 *   more details.
 *
 * Parameters:
 *   session (in)              - crypto session identifier.
 *   message (in)              - pointer to memory containing message to be
 *                             - signed.
 *   message_length (in)       - length of the message, in bytes.
 *   signature (out)           - buffer to hold the message signature. On
 *                             - return, it will contain the message signature
 *                             - generated with the device private RSA key using
 *                             - RSASSA-PSS.
 *   signature_length (in/out) - (in) length of the signature buffer, in bytes.
 *                             - (out) actual length of the signature
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_SHORT_BUFFER if the signature buffer is too small.
 *   OEMCrypto_ERROR_INVALID_RSA_KEY
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 6.
 */
OEMCryptoResult OEMCrypto_GenerateRSASignature(OEMCrypto_SESSION session,
                                               const uint8_t* message,
                                               size_t message_length,
                                               uint8_t* signature,
                                               size_t *signature_length);

/*
 * OEMCrypto_DeriveKeysFromSessionKey
 *
 * Description:
 *   Generates three secondary keys -- mac_key_server, mac_key_client, and
 *   encrypt_key -- for handling signing and content key decryption under the
 *   license server protocol for AES CTR mode.
 *
 *   This function is similar to OEMCrypto_GenerateDerivedKeys, except that it
 *   uses a session key to generate the secondary keys instead of the Widevine
 *   Keybox device key.  These two keys will be stored in secure memory until
 *   the next call to LoadKeys.  The session key is passed in encrypted by the
 *   device RSA public key, and must be decrypted with the RSA private key
 *   before use.  Once the enc_key and mac_keys have been generated, all calls
 *   to LoadKeys and RefreshKeys proceed in the same manner for license
 *   requests using RSA or using a Widevine keybox token.
 *
 * Parameters:
 *   session (in)                - crypto session identifier.
 *   enc_session_key (in)        - session key, encrypted with the device RSA key
 *                               - (from the device certifcate) using RSA-OAEP.
 *   enc_session_key_length (in) - length of session_key, in bytes.
 *   mac_key_context (in)        - pointer to memory containing context data for
 *                               - computing the HMAC generation key.
 *   mac_key_context_length (in) - length of the HMAC key context data, in bytes.
 *   enc_key_context (in)        - pointer to memory containing context data for
 *                               - computing the encryption key.
 *   enc_key_context_length (in) - length of the encryption key context data, in
 *                               - bytes.
 *
 * Returns:
 *   OEMCrypto_SUCCESS success
 *   OEMCrypto_ERROR_DEVICE_NOT_RSA_PROVISIONED
 *   OEMCrypto_ERROR_INVALID_SESSION
 *   OEMCrypto_ERROR_INVALID_CONTEXT
 *   OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 *   OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Version:
 *   This method changed in API version 8.
 */
OEMCryptoResult OEMCrypto_DeriveKeysFromSessionKey(OEMCrypto_SESSION session,
                                                   const uint8_t* enc_session_key,
                                                   size_t enc_session_key_length,
                                                   const uint8_t *mac_key_context,
                                                   size_t mac_key_context_length,
                                                   const uint8_t *enc_key_context,
                                                   size_t enc_key_context_length);


/*
 * OEMCrypto_APIVersion()
 *
 * Description:
 *   This function returns the current API version number.  Because this
 *   API is part of a shared library, the version number allows the calling
 *   application to avoid version mis-match errors.
 *
 *   There is a possibility that some API methods will be backwards compatible,
 *   or backwards compatible at a reduced security level.
 *
 *   There is no plan to introduce forward-compatibility.  I.e. applications
 *   will reject a library with a newer version of the API.
 *
 * Returns:
 *   The current version number.
 *
 * Version:
 *   This method should change in all API versions.
 */
uint32_t OEMCrypto_APIVersion();

/*
 * OEMCrypto_SecurityLevel()
 *
 * Description:
 *   This function returns the security level of the OEMCrypto library.
 *
 *   Since this function is spoofable, it is not relied on for security
 *   purposes.  It is for information only.
 *
 * Returns:
 *   A null terminated string.  Useful values are "L1", "L2" or "L3".
 *
 * Version:
 *   This method changed in API version 6.
 */
const char* OEMCrypto_SecurityLevel();

/*
 * OEMCryptoResult OEMCrypto_Generic_Encrypt
 *
 * This function encrypts a generic buffer of data using the current key.
 *
 * Verification:
 * The following checks should be performed.  If any check fails, an error is
 * returned, and the data is not encrypted.
 *
 * The control bit for the current key shall have the Allow_Encrypt set. If
 * not, return OEMCrypto_ERROR_UNKNOWN_FAILURE.
 *
 * Parameters:
 * [in] session: crypto session identifier.
 * [in] in_buffer: pointer to memory containing data to be encrypted.
 * [in] buffer_length: length of the buffer, in bytes.
 * [in] iv: IV for encrypting data.  Size is specified by the algorithm.
 * [in] algorithm: Specifies which encryption algorithm to use. See
 *      OEMCrypto_Algorithm for valid values.
 * [out] out_buffer: pointer to buffer in which encrypted data should be stored.
 *
 * Returns:
 * OEMCrypto_SUCCESS success
 * OEMCrypto_ERROR_KEY_EXPIRED
 * OEMCrypto_ERROR_NO_DEVICE_KEY
 * OEMCrypto_ERROR_INVALID_SESSION
 * OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Threading:
 * This function may be called simultaneously with functions on other sessions,
 * but not with other functions on this session.
 *
 * Version:
 *   This method changed in API version 7.
 */
OEMCryptoResult OEMCrypto_Generic_Encrypt(OEMCrypto_SESSION session,
                                          const uint8_t* in_buffer,
                                          size_t buffer_length,
                                          const uint8_t* iv,
                                          OEMCrypto_Algorithm algorithm,
                                          uint8_t* out_buffer);

/*
 * OEMCrypto_Generic_Decrypt
 *
 * This function decrypts a generic buffer of data using the current key.
 *
 * Verification:
 * The following checks should be performed.  If any check fails, an error is
 * returned, and the data is not decrypted.
 *
 * The control bit for the current key shall have the Allow_Decrypt set.  If
 * not, return OEMCrypto_ERROR_DECRYPT_FAILED.
 * If the current key’s control block has the Data_Path_Type bit set, then
 * return OEMCrypto_ERROR_DECRYPT_FAILED.
 * If the current key’s control block has the HDCP bit set, then return
 * OEMCrypto_ERROR_DECRYPT_FAILED.
 *
 * Parameters:
 * [in] session: crypto session identifier.
 * [in] in_buffer: pointer to memory containing data to be encrypted.
 * [in] buffer_length: length of the buffer, in bytes.
 * [in] iv: IV for encrypting data.  Size depends on the algorithm.
 * [in] algorithm: Specifies which encryption algorithm to use. See
 *      OEMCrypto_Algorithm for valid values.
 * [out] out_buffer: pointer to buffer in which decrypted data should be stored.
 *
 * Returns:
 * OEMCrypto_SUCCESS success
 * OEMCrypto_ERROR_KEY_EXPIRED
 * OEMCrypto_ERROR_NO_DEVICE_KEY
 * OEMCrypto_ERROR_INVALID_SESSION
 * OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Threading:
 * This function may be called simultaneously with functions on other sessions,
 * but not with other functions on this session.
 *
 * Version:
 *   This method changed in API version 7.
 */
OEMCryptoResult OEMCrypto_Generic_Decrypt(OEMCrypto_SESSION session,
                                          const uint8_t* in_buffer,
                                          size_t buffer_length,
                                          const uint8_t* iv,
                                          OEMCrypto_Algorithm algorithm,
                                          uint8_t* out_buffer);

/*
 * OEMCrypto_Generic_Sign
 *
 * This function signs a generic buffer of data using the current key.
 *
 * Verification
 * The following checks should be performed.  If any check fails,
 * an error is returned, and the signature is not generated.
 *
 * The control bit for the current key shall have the Allow_Sign set.
 *
 * Parameters
 * [in] session: crypto session identifier.
 * [in] in_buffer: pointer to memory containing data to be encrypted.
 * [in] buffer_length: length of the buffer, in bytes.
 * [in] algorithm: Specifies which algorithm to use.  See
 *      OEMCrypto_Algorithm for valid values.
 * [out] signature: pointer to buffer in which signature should be stored.
 * [in/out] signature_length: (in) length of the signature buffer, in bytes.
 *                            (out) actual length of the signature
 *
 * Returns
 * OEMCrypto_SUCCESS success
 * OEMCrypto_ERROR_SHORT_BUFFER if signature buffer is not large enough to hold
 *                              signature.
 * OEMCrypto_ERROR_KEY_EXPIRED
 * OEMCrypto_ERROR_DECRYPT_FAILED
 * OEMCrypto_ERROR_NO_DEVICE_KEY
 * OEMCrypto_ERROR_INVALID_SESSION
 * OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Threading
 * This function may be called simultaneously with functions on other sessions,
 * but not with other functions on this session.
 *
 * Version:
 *   This method changed in API version 7.
 */
OEMCryptoResult OEMCrypto_Generic_Sign(OEMCrypto_SESSION session,
                                       const uint8_t* in_buffer,
                                       size_t buffer_length,
                                       OEMCrypto_Algorithm algorithm,
                                       uint8_t* signature,
                                       size_t* signature_length);

/*
 * OEMCrypto_Generic_Verify
 * This function verfies the signature of a generic buffer of data using the
 * current key.
 *
 * Verification
 * The following checks should be performed.  If any check fails, an error is
 * returned, and the data is not signed.
 *
 * The control bit for the current key shall have the Allow_Verify set.
 * The signature of the message shall be computed, and the API shall verify the
 * computed signature matches the signature passed in.  If not, return
 * OEMCrypto_ERROR_SIGNATURE_FAILURE
 *
 * Parameters
 * [in] session: crypto session identifier.
 * [in] in_buffer: pointer to memory containing data to be encrypted.
 * [in] buffer_length: length of the buffer, in bytes.
 * [in] algorithm: Specifies which algorithm to use. Current valid value is
 *      HMAC_SHA256.
 * [in] signature: pointer to signature buffer.
 * [in] signature_length: length of the signature buffer, in bytes.
 *
 * Returns:
 * OEMCrypto_SUCCESS success
 * OEMCrypto_ERROR_KEY_EXPIRED
 * OEMCrypto_ERROR_SIGNATURE_FAILURE
 * OEMCrypto_ERROR_NO_DEVICE_KEY
 * OEMCrypto_ERROR_INVALID_SESSION
 * OEMCrypto_ERROR_INSUFFICIENT_RESOURCES
 * OEMCrypto_ERROR_UNKNOWN_FAILURE
 *
 * Threading:
 * This function may be called simultaneously with functions on other sessions,
 * but not with other functions on this session.
 *
 * Version:
 *   This method changed in API version 7.
 */
OEMCryptoResult OEMCrypto_Generic_Verify(OEMCrypto_SESSION session,
                                         const uint8_t* in_buffer,
                                         size_t buffer_length,
                                         OEMCrypto_Algorithm algorithm,
                                         const uint8_t* signature,
                                         size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif  // OEMCRYPTO_CENC_H_
