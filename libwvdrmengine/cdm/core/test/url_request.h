// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_TEST_URL_REQUEST_H_
#define CDM_TEST_URL_REQUEST_H_

#include <string>
#include "http_socket.h"
#include "wv_cdm_types.h"

namespace wvcdm {

// Provides simple HTTP request and response service.
// Only POST request method is implemented.
class UrlRequest {
 public:
  UrlRequest(const std::string& url, const std::string& port,
             bool secure_connect, bool chunk_transfer_mode);
  ~UrlRequest();

  void AppendChunkToUpload(const std::string& data);
  void ConcatenateChunkedResponse(const std::string http_response,
                                  std::string* modified_response);
  int GetResponse(std::string* message);
  int GetStatusCode(const std::string& response);
  bool is_connected() const { return is_connected_; }
  bool PostRequest(const std::string& data);
  bool PostRequestChunk(const std::string& data);
  bool PostCertRequestInQueryString(const std::string& data);

 private:
  static const unsigned int kHttpBufferSize = 4096;
  char buffer_[kHttpBufferSize];
  bool chunk_transfer_mode_;
  bool is_connected_;
  std::string port_;
  std::string request_;
  HttpSocket socket_;
  std::string server_url_;

  CORE_DISALLOW_COPY_AND_ASSIGN(UrlRequest);
};

};  // namespace wvcdm

#endif  // CDM_TEST_URL_REQUEST_H_
