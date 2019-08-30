// Copyright 2013 Google Inc. All Rights Reserved.

#ifndef CDM_TEST_HTTP_SOCKET_H_
#define CDM_TEST_HTTP_SOCKET_H_

#include <string>
#include "openssl/ssl.h"
#include "wv_cdm_types.h"

namespace wvcdm {

// Provides basic Linux based TCP socket interface.
class HttpSocket {
 public:
  HttpSocket();
  ~HttpSocket();

  void CloseSocket();
  bool Connect(const char* url, const std::string& port, bool enable_timeout,
               bool secure_connection);
  void GetDomainNameAndPathFromUrl(const std::string& url,
                                   std::string& domain_name,
                                   std::string& resource_path);
  const std::string& domain_name() const { return domain_name_; };
  const std::string& resource_path() const { return resource_path_; };
  int Read(char* data, int len);
  int Read(char* data, int len, int timeout_in_ms);
  int Write(const char* data, int len);

 private:
  void CloseSslContext(SSL_CTX* ctx) const {
    if (ctx) SSL_CTX_free(ctx);
  }
  SSL_CTX* InitSslContext(void);
  void ShowServerCertificate(const SSL* ssl);

  std::string domain_name_;
  bool secure_connect_;
  std::string resource_path_;
  int socket_fd_;
  SSL* ssl_;
  SSL_CTX* ssl_ctx_;
  bool timeout_enabled_;

  CORE_DISALLOW_COPY_AND_ASSIGN(HttpSocket);
};

};  // namespace wvcdm

#endif  // CDM_TEST_HTTP_SOCKET_H_
