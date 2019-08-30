// Copyright 2013 Google Inc. All Rights Reserved.

#include "http_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

#include "log.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/x509.h"

namespace wvcdm {

SSL_CTX* HttpSocket::InitSslContext(void) {
  const SSL_METHOD* method;
  SSL_CTX* ctx;

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  method = SSLv3_client_method();
  ctx = SSL_CTX_new(method);
  if (NULL == ctx) {
    LOGE("failed to create SSL context");
  }
  return ctx;
}

void HttpSocket::ShowServerCertificate(const SSL* ssl) {
  X509* cert;
  char* line;

  // gets the server certificate
  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    LOGV("server certificate:");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    LOGV("subject: %s", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    LOGV("issuer: %s", line);
    free(line);
    X509_free(cert);
  } else {
    LOGE("Failed to get server certificate");
  }
}

HttpSocket::HttpSocket()
    : secure_connect_(true),
      socket_fd_(-1),
      ssl_(NULL),
      ssl_ctx_(NULL),
      timeout_enabled_(false) {
  SSL_library_init();
}

HttpSocket::~HttpSocket() { CloseSocket(); }

void HttpSocket::CloseSocket() {
  if (socket_fd_ != -1) {
    close(socket_fd_);
    socket_fd_ = -1;
  }
  if (secure_connect_) {
    if (ssl_) {
      SSL_free(ssl_);
      ssl_ = NULL;
    }
    if (ssl_ctx_) {
      CloseSslContext(ssl_ctx_);
      ssl_ctx_ = NULL;
    }
  }
}

// Extracts the domain name and resource path from the input url parameter.
// The results are put in domain_name and resource_path respectively.
// The format of the url can begin with <protocol/scheme>:://domain server/...
// or dowmain server/resource_path
void HttpSocket::GetDomainNameAndPathFromUrl(const std::string& url,
                                             std::string& domain_name,
                                             std::string& resource_path) {
  domain_name.clear();
  resource_path.clear();

  size_t start = url.find("//");
  size_t end = url.npos;
  if (start != url.npos) {
    end = url.find("/", start + 2);
    if (end != url.npos) {
      domain_name.assign(url, start + 2, end - start - 2);
      resource_path.assign(url, end + 1, url.npos);
    } else {
      domain_name.assign(url, start + 2, url.npos);
    }
  } else {
    // no scheme/protocol in url
    end = url.find("/");
    if (end != url.npos) {
      domain_name.assign(url, 0, end);
      resource_path.assign(url, end + 1, url.npos);
    } else {
      domain_name.assign(url);
    }
  }
  // strips port number if present, e.g. https://www.domain.com:8888/...
  end = domain_name.find(":");
  if (end != domain_name.npos) {
    domain_name.erase(end);
  }
}

bool HttpSocket::Connect(const char* url, const std::string& port,
                         bool enable_timeout, bool secure_connection) {
  secure_connect_ = secure_connection;
  if (secure_connect_) ssl_ctx_ = InitSslContext();

  GetDomainNameAndPathFromUrl(url, domain_name_, resource_path_);

  socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd_ < 0) {
    LOGE("cannot open socket %d", errno);
    return false;
  }

  int reuse = 1;
  if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ==
      -1) {
    CloseSocket();
    LOGE("setsockopt error %d", errno);
    return false;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* addr_info = NULL;
  bool status = true;
  int ret = getaddrinfo(domain_name_.c_str(), port.c_str(), &hints, &addr_info);
  if (ret != 0) {
    CloseSocket();
    LOGE("getaddrinfo failed with %d", ret);
    status = false;
  } else {
    if (connect(socket_fd_, addr_info->ai_addr, addr_info->ai_addrlen) == -1) {
      CloseSocket();
      LOGE("cannot connect socket to %s, error=%d", domain_name_.c_str(),
           errno);
      status = false;
    }
  }
  timeout_enabled_ = enable_timeout;
  if (addr_info != NULL) {
    freeaddrinfo(addr_info);
  }

  if (!status) return false;

  // secures connection
  if (secure_connect_ && ssl_ctx_) {
    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_) {
      LOGE("failed SSL_new");
      return false;
    }

    BIO* a_bio = BIO_new_socket(socket_fd_, BIO_NOCLOSE);
    if (!a_bio) {
      LOGE("BIO_new_socket error");
      return false;
    }

    SSL_set_bio(ssl_, a_bio, a_bio);
    int ret = SSL_connect(ssl_);
    if (1 != ret) {
      char buf[256];
      LOGE("SSL_connect error:%s", ERR_error_string(ERR_get_error(), buf));
      return false;
    }
  }
  return true;
}

int HttpSocket::Read(char* data, int len) { return (Read(data, len, 0)); }

// makes non-blocking mode only during read, it supports timeout for read
// returns -1 for error, number of bytes read for success
int HttpSocket::Read(char* data, int len, int timeout_in_ms) {
  bool use_timeout = (timeout_enabled_ && (timeout_in_ms > 0));
  int original_flags = 0;
  if (use_timeout) {
    original_flags = fcntl(socket_fd_, F_GETFL, 0);
    if (original_flags == -1) {
      LOGE("fcntl error %d", errno);
      return -1;
    }
    if (fcntl(socket_fd_, F_SETFL, original_flags | O_NONBLOCK) == -1) {
      LOGE("fcntl error %d", errno);
      return -1;
    }
  }

  int total_read = 0;
  int read = 0;
  int to_read = len;
  while (to_read > 0) {
    if (use_timeout) {
      fd_set read_fds;
      struct timeval tv;
      tv.tv_sec = timeout_in_ms / 1000;
      tv.tv_usec = (timeout_in_ms % 1000) * 1000;
      FD_ZERO(&read_fds);
      FD_SET(socket_fd_, &read_fds);
      if (select(socket_fd_ + 1, &read_fds, NULL, NULL, &tv) == -1) {
        LOGE("select failed");
        break;
      }
      if (!FD_ISSET(socket_fd_, &read_fds)) {
        LOGD("socket read timeout");
        break;
      }
    }

    if (secure_connect_)
      read = SSL_read(ssl_, data, to_read);
    else
      read = recv(socket_fd_, data, to_read, 0);

    if (read > 0) {
      to_read -= read;
      data += read;
      total_read += read;
    } else if (read == 0) {
      // in blocking mode, zero read mean's peer closed.
      // in non-blocking mode, select said that there is data. so it should not
      // happen
      break;
    } else {
      LOGE("recv returned %d, error = %d", read, errno);
      break;
    }
  }

  if (use_timeout) {
    fcntl(socket_fd_, F_SETFL, original_flags);  // now blocking again
  }
  return total_read;
}

int HttpSocket::Write(const char* data, int len) {
  int total_sent = 0;
  int sent = 0;
  int to_send = len;
  while (to_send > 0) {
    if (secure_connect_)
      sent = SSL_write(ssl_, data, to_send);
    else
      sent = send(socket_fd_, data, to_send, 0);

    if (sent > 0) {
      to_send -= sent;
      data += sent;
      total_sent += sent;
    } else if (sent == 0) {
      usleep(10);  // retry later
    } else {
      LOGE("send returned error %d", errno);
    }
  }
  return total_sent;
}

}  // namespace wvcdm
