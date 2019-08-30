/*******************************************************************************
 *
 * Subset of the OEMCrypto APIs required for L1 support since they are called
 * from libwvm.
 *
 ******************************************************************************/

#ifndef _OEMCRYPTO_L1_H
#define _OEMCRYPTO_L1_H

typedef unsigned char   OEMCrypto_UINT8;
typedef char            OEMCrypto_INT8;
typedef unsigned int    OEMCrypto_UINT32;
typedef unsigned int    OEMCrypto_SECURE_BUFFER;


typedef enum OEMCryptoResult {
  OEMCrypto_SUCCESS = 0
} OEMCryptoResult;


#ifdef __cplusplus
extern "C" {
#endif

#define OEMCrypto_Initialize _oec01
#define OEMCrypto_Terminate _oec02
#define OEMCrypto_DecryptVideo _oec05
#define OEMCrypto_DecryptAudio _oec06

OEMCryptoResult OEMCrypto_Initialize(void);
OEMCryptoResult OEMCrypto_Terminate(void);
OEMCryptoResult OEMCrypto_DecryptVideo(const OEMCrypto_UINT8*,
                                       const OEMCrypto_UINT8*, const OEMCrypto_UINT32,
                                       OEMCrypto_UINT32, OEMCrypto_UINT32, OEMCrypto_UINT32 *);


OEMCryptoResult OEMCrypto_DecryptAudio(const OEMCrypto_UINT8*,
                                       const OEMCrypto_UINT8*, const OEMCrypto_UINT32,
                                       OEMCrypto_UINT8 *, OEMCrypto_UINT32 *);


#ifdef __cplusplus
}
#endif

#endif

/***************************** End of File *****************************/
