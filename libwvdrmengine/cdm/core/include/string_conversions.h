// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_BASE_STRING_CONVERSIONS_H_
#define CDM_BASE_STRING_CONVERSIONS_H_

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace wvcdm {

std::vector<uint8_t> a2b_hex(const std::string& b);
std::string a2bs_hex(const std::string& b);
std::string b2a_hex(const std::vector<uint8_t>& b);
std::string b2a_hex(const std::string& b);
std::string Base64SafeEncode(const std::vector<uint8_t>& bin_input);
std::string Base64SafeEncodeNoPad(const std::vector<uint8_t>& bin_input);
std::vector<uint8_t> Base64SafeDecode(const std::string& bin_input);
std::string HexEncode(const uint8_t* bytes, unsigned size);
std::string IntToString(int value);
std::string UintToString(unsigned int value);

};  // namespace wvcdm

#endif  // CDM_BASE_STRING_CONVERSIONS_H_
