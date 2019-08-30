// Copyright 2013 Google Inc. All Rights Reserved.

#include "url_request.h"

#include <errno.h>
#include <sstream>

#include "http_socket.h"
#include "log.h"
#include "string_conversions.h"

namespace wvcdm {

UrlRequest::UrlRequest(const std::string& url, const std::string& port,
                       bool secure_connection, bool chunk_transfer_mode)
    : chunk_transfer_mode_(chunk_transfer_mode),
      is_connected_(false),
      port_("80"),
      request_(""),
      server_url_(url) {
  if (!port.empty()) {
    port_.assign(port);
  }
  if (socket_.Connect((server_url_).c_str(), port_, true, secure_connection)) {
    is_connected_ = true;
  } else {
    LOGE("failed to connect to %s, port=%s", socket_.domain_name().c_str(),
         port.c_str());
  }
}

UrlRequest::~UrlRequest() { socket_.CloseSocket(); }

void UrlRequest::AppendChunkToUpload(const std::string& data) {
  // format of chunk:
  //   size of chunk in hex\r\n
  //   data\r\n
  //   . . .
  //   0\r\n

  // buffer to store length of chunk
  memset(buffer_, 0, kHttpBufferSize);
  snprintf(buffer_, kHttpBufferSize, "%zx\r\n", data.size());
  request_.append(buffer_);  // appends size of chunk
  LOGD("...\r\n%s", request_.c_str());
  request_.append(data);
  request_.append("\r\n");  // marks end of data
}

// Concatenate all chunks into one blob and returns the response with
// header information.
void UrlRequest::ConcatenateChunkedResponse(const std::string http_response,
                                            std::string* modified_response) {
  if (http_response.empty()) return;

  modified_response->clear();
  const std::string kChunkedTag = "Transfer-Encoding: chunked\r\n\r\n";
  size_t chunked_tag_pos = http_response.find(kChunkedTag);
  if (std::string::npos != chunked_tag_pos) {
    // processes chunked encoding
    size_t chunk_size = 0;
    size_t chunk_size_pos = chunked_tag_pos + kChunkedTag.size();
    sscanf(&http_response[chunk_size_pos], "%zx", &chunk_size);
    if (chunk_size > http_response.size()) {
      // precaution, in case we misread chunk size
      LOGE("invalid chunk size %u", chunk_size);
      return;
    }

    // Search for chunks in the following format:
    // header
    // chunk size\r\n  <-- chunk_size_pos @ beginning of chunk size
    // chunk data\r\n  <-- chunk_pos @ beginning of chunk data
    // chunk size\r\n
    // chunk data\r\n
    // 0\r\n
    const std::string kCrLf = "\r\n";
    size_t chunk_pos = http_response.find(kCrLf, chunk_size_pos);
    modified_response->assign(http_response, 0, chunk_size_pos);

    while ((chunk_size > 0) && (std::string::npos != chunk_pos)) {
      chunk_pos += kCrLf.size();
      modified_response->append(http_response, chunk_pos, chunk_size);

      // Search for next chunk
      chunk_size_pos = chunk_pos + chunk_size + kCrLf.size();
      sscanf(&http_response[chunk_size_pos], "%zx", &chunk_size);
      if (chunk_size > http_response.size()) {
        // precaution, in case we misread chunk size
        LOGE("invalid chunk size %u", chunk_size);
        break;
      }
      chunk_pos = http_response.find(kCrLf, chunk_size_pos);
    }
  } else {
    // Response is not chunked encoded
    modified_response->assign(http_response);
  }
}

int UrlRequest::GetResponse(std::string* message) {
  message->clear();

  std::string response;
  const int kTimeoutInMs = 3000;
  int bytes = 0;
  do {
    memset(buffer_, 0, kHttpBufferSize);
    bytes = socket_.Read(buffer_, kHttpBufferSize, kTimeoutInMs);
    if (bytes > 0) {
      response.append(buffer_, bytes);
    } else {
      if (bytes < 0) LOGE("read error = ", errno);
      // bytes == 0 indicates nothing to read
    }
  } while (bytes > 0);

  ConcatenateChunkedResponse(response, message);
  LOGD("HTTP response: (%d): %s", message->size(), b2a_hex(*message).c_str());
  return message->size();
}

int UrlRequest::GetStatusCode(const std::string& response) {
  const std::string kHttpVersion("HTTP/1.1");

  int status_code = -1;
  size_t pos = response.find(kHttpVersion);
  if (pos != std::string::npos) {
    pos += kHttpVersion.size();
    sscanf(response.substr(pos).c_str(), "%d", &status_code);
  }
  return status_code;
}

bool UrlRequest::PostRequestChunk(const std::string& data) {
  request_.assign("POST /");
  request_.append(socket_.resource_path());
  request_.append(" HTTP/1.1\r\n");
  request_.append("Host: ");
  request_.append(socket_.domain_name());
  request_.append("\r\nConnection: Keep-Alive\r\n");
  request_.append("Transfer-Encoding: chunked\r\n");
  request_.append("User-Agent: Widevine CDM v1.0\r\n");
  request_.append("Accept-Encoding: gzip,deflate\r\n");
  request_.append("Accept-Language: en-us,fr\r\n");
  request_.append("Accept-Charset: iso-8859-1,*,utf-8\r\n");
  request_.append("\r\n");  // empty line to terminate header

  // calls AppendChunkToUpload repeatedly for multiple chunks
  AppendChunkToUpload(data);

  // terminates last chunk with 0\r\n, then ends header with an empty line
  request_.append("0\r\n\r\n");

  socket_.Write(request_.c_str(), request_.size());
  return true;
}

bool UrlRequest::PostRequest(const std::string& data) {
  if (chunk_transfer_mode_) {
    return PostRequestChunk(data);
  }
  request_.assign("POST /");
  request_.append(socket_.resource_path());
  request_.append(" HTTP/1.1\r\n");
  request_.append("Host: ");
  request_.append(socket_.domain_name());
  request_.append("\r\nConnection: Keep-Alive\r\n");
  request_.append("User-Agent: Widevine CDM v1.0\r\n");
  request_.append("Accept-Encoding: gzip,deflate\r\n");
  request_.append("Accept-Language: en-us,fr\r\n");
  request_.append("Accept-Charset: iso-8859-1,*,utf-8\r\n");
  std::ostringstream ss;
  ss << data.size();
  request_.append("Content-Length: ");
  request_.append(ss.str());
  request_.append("\r\n\r\n");
  request_.append(data);

  // terminates with \r\n, then ends with an empty line
  request_.append("\r\n\r\n");

  socket_.Write(request_.c_str(), request_.size());
  LOGD("HTTP request: (%d): %s", request_.size(), request_.c_str());
  LOGD("HTTP request: (%d): %s", request_.size(), b2a_hex(request_).c_str());
  return true;
}

bool UrlRequest::PostCertRequestInQueryString(const std::string& data) {
  request_.assign("POST /");
  request_.append(socket_.resource_path());
  request_.append("&signedRequest=");
  request_.append(data);
  request_.append(" HTTP/1.1\r\n");
  request_.append("User-Agent: Widevine CDM v1.0\r\n");
  request_.append("Host: ");
  request_.append(socket_.domain_name());
  request_.append("\r\nAccept: */*");
  request_.append("\r\nContent-Type: application/json");
  request_.append("\r\nContent-Length: 0");
  request_.append("\r\n");  // empty line to terminate header
  request_.append("\r\n");  // terminates the request

  socket_.Write(request_.c_str(), request_.size());
  LOGD("HTTP request: (%d): %s", request_.size(), request_.c_str());
  LOGD("HTTP request: (%d): %s", request_.size(), b2a_hex(request_).c_str());
  return true;
}

}  // namespace wvcdm
