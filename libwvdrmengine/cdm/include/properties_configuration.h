// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_PROPERTIES_CONFIGURATION_H_
#define CDM_BASE_PROPERTIES_CONFIGURATION_H_

#include "wv_cdm_constants.h"
#include "properties.h"

namespace wvcdm {

// If false begin license usage on first playback
const bool kPropertyBeginLicenseUsageWhenReceived = false;

// If false, calls to Generate Key request, after the first one,
// will result in a renewal request being generated
const bool kPropertyRequireExplicitRenewRequest = false;

// Set only one of the three below to true. If secure buffer
// is selected, fallback to userspace buffers may occur
// if L1/L2 OEMCrypto APIs fail
const bool kPropertyOemCryptoUseSecureBuffers = true;
const bool kPropertyOemCryptoUseFifo = false;
const bool kPropertyOemCryptoUseUserSpaceBuffers = false;

// If false, keyboxes will be used as client identification
// and passed as the token in the license request
const bool kPropertyUseCertificatesAsIdentification = true;

// If false, extraction of widevine PSSH information from the PSSH box
// takes place external to the CDM. This will become the default behaviour
// once all platforms support it (b/9465346)
const bool kExtractPsshData = true;

// If true, session_id parameter to CdmEngine::Decrypt can be empty; the
// function will try to find out the session_id from the key_id.
const bool kDecryptWithEmptySessionSupport = false;

// If true, device files will be moved to the directory specified by
// Properties::GetDeviceFilesBasePath
const bool kSecurityLevelPathBackwardCompatibilitySupport = true;

} // namespace wvcdm

#endif  // CDM_BASE_WV_PROPERTIES_CONFIGURATION_H_
