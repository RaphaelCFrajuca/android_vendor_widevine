// Copyright 2013 Google Inc. All Rights Reserved.

#include "string_conversions.h"

#include <ctype.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vector>

#include "log.h"
#include "modp_b64w.h"

namespace wvcdm {

static bool CharToDigit(char ch, unsigned char* digit) {
  if (ch >= '0' && ch <= '9') {
    *digit = ch - '0';
  } else {
    ch = tolower(ch);
    if ((ch >= 'a') && (ch <= 'f')) {
      *digit = ch - 'a' + 10;
    } else {
      return false;
    }
  }
  return true;
}

// converts an ascii hex string(2 bytes per digit) into a decimal byte string
std::vector<uint8_t> a2b_hex(const std::string& byte) {
  std::vector<uint8_t> array;
  unsigned int count = byte.size();
  if (count == 0 || (count % 2) != 0) {
    LOGE("Invalid input size %u for string %s", count, byte.c_str());
    return array;
  }

  for (unsigned int i = 0; i < count / 2; ++i) {
    unsigned char msb = 0;  // most significant 4 bits
    unsigned char lsb = 0;  // least significant 4 bits
    if (!CharToDigit(byte[i * 2], &msb) ||
        !CharToDigit(byte[i * 2 + 1], &lsb)) {
      LOGE("Invalid hex value %c%c at index %d", byte[i*2], byte[i*2+1], i);
      return array;
    }
    array.push_back((msb << 4) | lsb);
  }
  return array;
}

std::string a2bs_hex(const std::string& byte) {
  std::vector<uint8_t> array = a2b_hex(byte);
  return std::string(array.begin(), array.end());
}

std::string b2a_hex(const std::vector<uint8_t>& byte) {
  return HexEncode(&byte[0], byte.size());
}

std::string b2a_hex(const std::string& byte) {
  return HexEncode(reinterpret_cast<const uint8_t *>(byte.data()),
                   byte.length());
}

// Filename-friendly base64 encoding (RFC4648), commonly referred as
// Base64WebSafeEncode.
// This is the encoding required by GooglePlay to interface with the
// provisioning server's Apiary interface as well as for certain license server
// transactions.  It is also used for logging certain strings.
// The difference between web safe encoding vs regular encoding is that
// the web safe version replaces '+' with '-' and '/' with '_'.
std::string Base64SafeEncode(const std::vector<uint8_t>& bin_input) {
  if (bin_input.empty()) {
    return std::string();
  }

  int in_size = bin_input.size();
  std::string b64_output(modp_b64w_encode_len(in_size), 0);

  int out_size = modp_b64w_encode(&b64_output[0],
                                 reinterpret_cast<const char*>(&bin_input[0]),
                                 in_size);
  if (out_size == -1) {
    LOGE("Base64SafeEncode failed");
    return std::string();
  }

  b64_output.resize(out_size);
  return b64_output;
}

std::string Base64SafeEncodeNoPad(const std::vector<uint8_t>& bin_input) {
  std::string b64_output = Base64SafeEncode(bin_input);
  // Output size: ceiling [ bin_input.size() * 4 / 3 ].
  b64_output.resize((bin_input.size() * 4 + 2) / 3);
  return b64_output;
}

// Decode for Filename-friendly base64 encoding (RFC4648), commonly referred
// as Base64WebSafeDecode.
std::vector<uint8_t> Base64SafeDecode(const std::string& b64_input) {
  if (b64_input.empty()) {
    return std::vector<uint8_t>();
  }

  int in_size = b64_input.size();
  std::vector<uint8_t> bin_output(modp_b64w_decode_len(in_size), 0);
  int out_size = modp_b64w_decode(reinterpret_cast<char*>(&bin_output[0]),
                                 b64_input.data(),
                                 in_size);
  if (out_size == -1) {
    LOGE("Base64SafeDecode failed");
    return std::vector<uint8_t>(0);
  }

  bin_output.resize(out_size);
  return bin_output;
}

std::string HexEncode(const uint8_t* in_buffer, unsigned int size) {
  static const char kHexChars[] = "0123456789ABCDEF";

  // Each input byte creates two output hex characters.
  std::string out_buffer(size * 2, '\0');

  for (unsigned int i = 0; i < size; ++i) {
    char byte = in_buffer[i];
    out_buffer[(i << 1)] = kHexChars[(byte >> 4) & 0xf];
    out_buffer[(i << 1) + 1] = kHexChars[byte & 0xf];
  }
  return out_buffer;
}

std::string IntToString(int value) {
  // log10(2) ~= 0.3 bytes needed per bit or per byte log10(2**8) ~= 2.4.
  // So round up to allocate 3 output characters per byte, plus 1 for '-'.
  const int kOutputBufSize = 3 * sizeof(int) + 1;
  char buffer[kOutputBufSize];
  memset(buffer, 0, kOutputBufSize);
  snprintf(buffer, kOutputBufSize, "%d", value);

  std::string out_string(buffer, sizeof(buffer));
  return out_string;
}

std::string UintToString(unsigned int value) {
  // log10(2) ~= 0.3 bytes needed per bit or per byte log10(2**8) ~= 2.4.
  // So round up to allocate 3 output characters per byte.
  const int kOutputBufSize = 3 * sizeof(unsigned int);
  char buffer[kOutputBufSize];
  memset(buffer, 0, kOutputBufSize);
  snprintf(buffer, kOutputBufSize, "%u", value);

  std::string out_string(buffer, sizeof(buffer));
  return out_string;
}

};  // namespace wvcdm
