// Copyright 2012 Google Inc. All Rights Reserved.

#include "buffer_reader.h"

#include "log.h"

namespace wvcdm {

bool BufferReader::Read1(uint8_t* v) {
  if (!HasBytes(1)) {
    LOGE("BufferReader::Read1 : Failure while parsing: Not enough bytes (1)");
    return false;
  }

  *v = buf_[pos_++];
  return true;
}

// Internal implementation of multi-byte reads
template<typename T> bool BufferReader::Read(T* v) {
  if (!HasBytes(sizeof(T))) {
    LOGE("BufferReader::Read<T> : Failure while parsing: Not enough bytes (%u)", sizeof(T));
    return false;
  }

  T tmp = 0;
  for (size_t i = 0; i < sizeof(T); i++) {
    tmp <<= 8;
    tmp += buf_[pos_++];
  }
  *v = tmp;
  return true;
}

bool BufferReader::Read2(uint16_t* v) { return Read(v); }
bool BufferReader::Read2s(int16_t* v) { return Read(v); }
bool BufferReader::Read4(uint32_t* v) { return Read(v); }
bool BufferReader::Read4s(int32_t* v) { return Read(v); }
bool BufferReader::Read8(uint64_t* v) { return Read(v); }
bool BufferReader::Read8s(int64_t* v) { return Read(v); }

bool BufferReader::ReadString(std::string* str, int count) {
  if (!HasBytes(count)) {
    LOGE("BufferReader::ReadString : Failure while parsing: Not enough bytes (%d)", count);
    return false;
  }

  str->assign(buf_ + pos_, buf_ + pos_ + count);
  pos_ += count;
  return true;
}

bool BufferReader::ReadVec(std::vector<uint8_t>* vec, int count) {
  if (!HasBytes(count)) {
    LOGE("BufferReader::ReadVec : Failure while parsing: Not enough bytes (%d)", count);
    return false;
  }

  vec->clear();
  vec->insert(vec->end(), buf_ + pos_, buf_ + pos_ + count);
  pos_ += count;
  return true;
}

bool BufferReader::SkipBytes(int bytes) {
  if (!HasBytes(bytes)) {
    LOGE("BufferReader::SkipBytes : Failure while parsing: Not enough bytes (%d)", bytes);
    return false;
  }

  pos_ += bytes;
  return true;
}

bool BufferReader::Read4Into8(uint64_t* v) {
  uint32_t tmp;
  if (!Read4(&tmp)) {
    return false;
  }
  *v = tmp;
  return true;
}

bool BufferReader::Read4sInto8s(int64_t* v) {
  // Beware of the need for sign extension.
  int32_t tmp;
  if (!Read4s(&tmp)) {
    return false;
  }
  *v = tmp;
  return true;
}

}  // namespace wvcdm
