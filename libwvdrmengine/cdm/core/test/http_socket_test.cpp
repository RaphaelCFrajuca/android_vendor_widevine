// Copyright 2013 Google Inc. All Rights Reserved.

#include <errno.h>
#include "gtest/gtest.h"
#include "http_socket.h"
#include "log.h"
#include "string_conversions.h"
#include "url_request.h"

namespace {
const std::string kHttpsTestServer("https://www.google.com");
std::string gTestServer(kHttpsTestServer);
std::string gTestData("Hello");
const int kHttpBufferSize = 4096;
char gBuffer[kHttpBufferSize];
}

namespace wvcdm {

class HttpSocketTest : public testing::Test {
 public:
  HttpSocketTest() {}
  ~HttpSocketTest() { socket_.CloseSocket(); }

 protected:
  bool Connect(const std::string& server_url, bool secure_connection) {

    std::string port = secure_connection ? "443" : "80";
    if (socket_.Connect(server_url.c_str(), port, true, secure_connection)) {
      LOGD("connected to %s", socket_.domain_name().c_str());
    } else {
      LOGE("failed to connect to %s", socket_.domain_name().c_str());
      return false;
    }
    return true;
  }

  bool PostRequest(const std::string& data) {
    std::string request("POST ");
    if (socket_.resource_path().empty())
      request.append(socket_.domain_name());
    else
      request.append(socket_.resource_path());
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(socket_.domain_name());
    request.append("\r\nUser-Agent: httpSocketTest/1.0\r\n");
    request.append("Content-Length: ");
    memset(gBuffer, 0, kHttpBufferSize);
    snprintf(gBuffer, kHttpBufferSize, "%d\r\n", static_cast<int>(data.size()));
    request.append(gBuffer);
    request.append("Content-Type: multipart/form-data\r\n");

    // newline terminates header
    request.append("\r\n");

    // append data
    request.append(data);
    socket_.Write(request.c_str(), request.size());
    LOGD("request: %s", request.c_str());
    return true;
  }

  bool GetResponse() {
    int bytes = socket_.Read(gBuffer, kHttpBufferSize, 1000);
    if (bytes < 0) {
      LOGE("read error = ", errno);
      return false;
    } else {
      LOGD("read %d bytes", bytes);
      std::string response(gBuffer, bytes);
      LOGD("response: %s", response.c_str());
      LOGD("end response dump");
      return true;
    }
  }

  HttpSocket socket_;
  std::string domain_name_;
  std::string resource_path_;
};

TEST_F(HttpSocketTest, GetDomainNameAndPathFromUrlTest) {
  socket_.GetDomainNameAndPathFromUrl(
      "https://code.google.com/p/googletest/wiki/Primer", domain_name_,
      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("p/googletest/wiki/Primer", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl(
      "http://code.google.com/p/googletest/wiki/Primer/", domain_name_,
      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("p/googletest/wiki/Primer/", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("http://code.google.com/", domain_name_,
                                      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("http://code.google.com", domain_name_,
                                      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl(
      "code.google.com/p/googletest/wiki/Primer", domain_name_, resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("p/googletest/wiki/Primer", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("code.google.com", domain_name_,
                                      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("code.google.com/", domain_name_,
                                      resource_path_);
  EXPECT_STREQ("code.google.com", domain_name_.c_str());
  EXPECT_STREQ("", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("", domain_name_, resource_path_);
  EXPECT_TRUE(domain_name_.empty());
  EXPECT_TRUE(resource_path_.empty());

  socket_.GetDomainNameAndPathFromUrl("http://10.21.200.68:8888/drm",
                                      domain_name_, resource_path_);
  EXPECT_STREQ("10.21.200.68", domain_name_.c_str());
  EXPECT_STREQ("drm", resource_path_.c_str());

  socket_.GetDomainNameAndPathFromUrl("http://10.21.200.68:8888", domain_name_,
                                      resource_path_);
  EXPECT_STREQ("10.21.200.68", domain_name_.c_str());
  EXPECT_TRUE(resource_path_.empty());
}

TEST_F(HttpSocketTest, ConnectTest) {
  const bool kUseSecureConnection = true;

  if (gTestServer.find("https") != std::string::npos) {
    EXPECT_TRUE(Connect(gTestServer, kUseSecureConnection));
    socket_.CloseSocket();

    // https connection allows insecure connection through port 80 as well
    EXPECT_TRUE(Connect(gTestServer, !kUseSecureConnection));
    socket_.CloseSocket();
  } else {
    EXPECT_TRUE(Connect(gTestServer, !kUseSecureConnection));
    socket_.CloseSocket();

    // Test for the case that non-https connection must not use port 443
    EXPECT_FALSE(Connect(gTestServer, kUseSecureConnection));
    socket_.CloseSocket();
  }

  EXPECT_FALSE(Connect("ww.g.c", kUseSecureConnection));
  socket_.CloseSocket();

  EXPECT_FALSE(Connect("ww.g.c", !kUseSecureConnection));
  socket_.CloseSocket();
}

TEST_F(HttpSocketTest, RoundTripTest) {
  int secure_connection =
      (gTestServer.find("https") != std::string::npos) ? true : false;
  ASSERT_TRUE(Connect(gTestServer, secure_connection));
  EXPECT_TRUE(PostRequest(gTestData));
  GetResponse();
  socket_.CloseSocket();
}

}  // namespace wvcdm

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  std::string temp;
  std::string test_server(kHttpsTestServer);
  std::string test_data(gTestData);
  for (int i = 1; i < argc; i++) {
    temp.assign(argv[i]);
    if (temp.find("--server=") == 0) {
      gTestServer.assign(temp.substr(strlen("--server=")));
    } else if (temp.find("--data=") == 0) {
      gTestData.assign(temp.substr(strlen("--data=")));
    } else {
      std::cout << "error: unknown option '" << argv[i] << "'" << std::endl;
      std::cout << "usage: http_socket_test [options]" << std::endl
                << std::endl;
      std::cout << std::setw(30) << std::left << "    --server=<server_url>";
      std::cout
          << "configure the test server url, please include http[s] in the url"
          << std::endl;
      std::cout << std::setw(30) << std::left << " ";
      std::cout << "default: " << test_server << std::endl;
      std::cout << std::setw(30) << std::left << "    --data=<data>";
      std::cout << "configure data to send, in ascii string format"
                << std::endl;
      std::cout << std::setw(30) << std::left << " ";
      std::cout << "default: " << test_data << std::endl << std::endl;
      return 0;
    }
  }

  std::cout << std::endl;
  std::cout << "Server: " << gTestServer << std::endl;
  std::cout << "Data: " << gTestData << std::endl;

  return RUN_ALL_TESTS();
}
