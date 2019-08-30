// Copyright 2013 Google Inc. All Rights Reserved.

#include "device_files.h"
#include "file_store.h"
#include "gtest/gtest.h"
#include "properties.h"
#include "test_vectors.h"

namespace {
const std::string kTestDirName = "test";
const std::string kTestFileName = "test.txt";
const std::string kTestFileName2 = "test2.txt";
const std::string kTestFileNameExt = ".txt";
const std::string kWildcard = "*";
}  // namespace

namespace wvcdm {

class FileTest : public testing::Test {
 protected:
  virtual void SetUp() { CreateTestDir(); }
  virtual void TearDown() { RemoveTestDir(); }

  void CreateTestDir() {
    File file;
    if (!file.Exists(test_vectors::kTestDir)) {
      EXPECT_TRUE(file.CreateDirectory(test_vectors::kTestDir));
    }
    EXPECT_TRUE(file.Exists(test_vectors::kTestDir));
  }

  void RemoveTestDir() {
    File file;
    EXPECT_TRUE(file.Remove(test_vectors::kTestDir));
  }

  std::string GenerateRandomData(uint32_t len) {
    std::string data(len, 0);
    for (size_t i = 0; i < len; i++) {
      data[i] = rand() % 256;
    }
    return data;
  }
};

TEST_F(FileTest, FileExists) {
  File file;
  EXPECT_TRUE(file.Exists(test_vectors::kFileExists));
  EXPECT_TRUE(file.Exists(test_vectors::kDirExists));
  EXPECT_FALSE(file.Exists(test_vectors::kFileDoesNotExist));
  EXPECT_FALSE(file.Exists(test_vectors::kDirDoesNotExist));
}

TEST_F(FileTest, CreateDirectory) {
  File file;
  std::string dir_wo_delimiter =
      test_vectors::kTestDir.substr(0, test_vectors::kTestDir.size() - 1);
  if (file.Exists(dir_wo_delimiter)) EXPECT_TRUE(file.Remove(dir_wo_delimiter));
  EXPECT_FALSE(file.Exists(dir_wo_delimiter));
  EXPECT_TRUE(file.CreateDirectory(dir_wo_delimiter));
  EXPECT_TRUE(file.Exists(dir_wo_delimiter));
  EXPECT_TRUE(file.Remove(dir_wo_delimiter));
  EXPECT_TRUE(file.CreateDirectory(test_vectors::kTestDir));
  EXPECT_TRUE(file.Exists(test_vectors::kTestDir));
  EXPECT_TRUE(file.Remove(test_vectors::kTestDir));
}

TEST_F(FileTest, RemoveDir) {
  File file;
  EXPECT_TRUE(file.Remove(test_vectors::kTestDir));
  EXPECT_FALSE(file.Exists(test_vectors::kTestDir));
}

TEST_F(FileTest, OpenFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File handle;
  EXPECT_TRUE(handle.Remove(path));

  File file;
  EXPECT_TRUE(file.Open(path, File::kCreate));
  file.Close();

  EXPECT_TRUE(handle.Exists(path));
}

TEST_F(FileTest, RemoveDirAndFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;

  File file;
  EXPECT_TRUE(file.Open(path, File::kCreate));
  file.Close();
  EXPECT_TRUE(file.Exists(path));
  EXPECT_TRUE(file.Remove(path));
  EXPECT_FALSE(file.Exists(path));

  EXPECT_TRUE(file.Open(path, File::kCreate));
  file.Close();
  EXPECT_TRUE(file.Exists(path));
  RemoveTestDir();
  EXPECT_FALSE(file.Exists(test_vectors::kTestDir));
  EXPECT_FALSE(file.Exists(path));
}

TEST_F(FileTest, RemoveWildcardFiles) {
  std::string path1 = test_vectors::kTestDir + kTestFileName;
  std::string path2 = test_vectors::kTestDir + kTestFileName2;
  std::string wildcard_path =
      test_vectors::kTestDir + kWildcard + kTestFileNameExt;

  File file;
  EXPECT_TRUE(file.Open(path1, File::kCreate));
  file.Close();
  EXPECT_TRUE(file.Open(path2, File::kCreate));
  file.Close();
  EXPECT_TRUE(file.Exists(path1));
  EXPECT_TRUE(file.Exists(path2));
  EXPECT_TRUE(file.Remove(wildcard_path));
  EXPECT_FALSE(file.Exists(path1));
  EXPECT_FALSE(file.Exists(path2));
}

TEST_F(FileTest, IsDir) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  EXPECT_TRUE(file.Open(path, File::kCreate));
  file.Close();

  EXPECT_TRUE(file.Exists(path));
  EXPECT_TRUE(file.Exists(test_vectors::kTestDir));
  EXPECT_FALSE(file.IsDirectory(path));
  EXPECT_TRUE(file.IsDirectory(test_vectors::kTestDir));
}

TEST_F(FileTest, IsRegularFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  EXPECT_TRUE(file.Open(path, File::kCreate));
  file.Close();

  EXPECT_TRUE(file.Exists(path));
  EXPECT_TRUE(file.Exists(test_vectors::kTestDir));
  EXPECT_TRUE(file.IsRegularFile(path));
  EXPECT_FALSE(file.IsRegularFile(test_vectors::kTestDir));
}

TEST_F(FileTest, FileSize) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  file.Remove(path);

  std::string write_data = GenerateRandomData(600);
  File wr_file;
  EXPECT_TRUE(wr_file.Open(path, File::kCreate | File::kBinary));
  EXPECT_TRUE(wr_file.Write(write_data.data(), write_data.size()));
  wr_file.Close();
  EXPECT_TRUE(file.Exists(path));

  EXPECT_EQ(static_cast<ssize_t>(write_data.size()), file.FileSize(path));
}

TEST_F(FileTest, WriteReadTextFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  file.Remove(path);

  std::string write_data = "This is a test";
  File wr_file;
  EXPECT_TRUE(wr_file.Open(path, File::kCreate));
  EXPECT_TRUE(wr_file.Write(write_data.data(), write_data.size()));
  wr_file.Close();
  EXPECT_TRUE(file.Exists(path));

  std::string read_data;
  read_data.resize(file.FileSize(path));
  File rd_file;
  EXPECT_TRUE(rd_file.Open(path, File::kReadOnly));
  EXPECT_TRUE(rd_file.Read(&read_data[0], read_data.size()));
  rd_file.Close();
  EXPECT_EQ(write_data, read_data);
}

TEST_F(FileTest, WriteReadBinaryFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  file.Remove(path);

  std::string write_data = GenerateRandomData(600);
  File wr_file;
  EXPECT_TRUE(wr_file.Open(path, File::kCreate | File::kBinary));
  EXPECT_TRUE(wr_file.Write(write_data.data(), write_data.size()));
  wr_file.Close();
  EXPECT_TRUE(file.Exists(path));

  std::string read_data;
  read_data.resize(file.FileSize(path));
  File rd_file;
  EXPECT_TRUE(rd_file.Open(path, File::kReadOnly));
  EXPECT_TRUE(rd_file.Read(&read_data[0], read_data.size()));
  rd_file.Close();
  EXPECT_EQ(write_data, read_data);
}

TEST_F(FileTest, CopyFile) {
  std::string path = test_vectors::kTestDir + kTestFileName;
  File file;
  file.Remove(path);

  std::string write_data = GenerateRandomData(600);
  File wr_file;
  EXPECT_TRUE(wr_file.Open(path, File::kCreate | File::kBinary));
  EXPECT_TRUE(wr_file.Write(write_data.data(), write_data.size()));
  wr_file.Close();
  EXPECT_TRUE(file.Exists(path));

  std::string path_copy = test_vectors::kTestDir + kTestFileName2;
  EXPECT_FALSE(file.Exists(path_copy));
  EXPECT_TRUE(file.Copy(path, path_copy));

  std::string read_data;
  read_data.resize(file.FileSize(path_copy));
  File rd_file;
  EXPECT_TRUE(rd_file.Open(path_copy, File::kReadOnly));
  EXPECT_TRUE(rd_file.Read(&read_data[0], read_data.size()));
  rd_file.Close();
  EXPECT_EQ(write_data, read_data);
  EXPECT_EQ(file.FileSize(path), file.FileSize(path_copy));
}

TEST_F(FileTest, ListEmptyDirectory) {
  std::vector<std::string> files;
  File file;
  EXPECT_TRUE(file.List(test_vectors::kTestDir, &files));
  EXPECT_EQ(0u, files.size());
}

TEST_F(FileTest, ListFiles) {
  File file;
  std::string path = test_vectors::kTestDir + kTestDirName;
  EXPECT_TRUE(file.CreateDirectory(path));

  path = test_vectors::kTestDir + kTestFileName;
  std::string write_data = GenerateRandomData(600);
  EXPECT_TRUE(file.Open(path, File::kCreate | File::kBinary));
  EXPECT_TRUE(file.Write(write_data.data(), write_data.size()));
  file.Close();
  EXPECT_TRUE(file.Exists(path));

  path = test_vectors::kTestDir + kTestFileName2;
  write_data = GenerateRandomData(600);
  EXPECT_TRUE(file.Open(path, File::kCreate | File::kBinary));
  EXPECT_TRUE(file.Write(write_data.data(), write_data.size()));
  file.Close();
  EXPECT_TRUE(file.Exists(path));

  std::vector<std::string> files;
  EXPECT_TRUE(file.List(test_vectors::kTestDir, &files));
  EXPECT_EQ(3u, files.size());

  for (size_t i = 0; i < files.size(); ++i) {
    EXPECT_TRUE(files[i].compare(kTestDirName) == 0 ||
                files[i].compare(kTestFileName) == 0 ||
                files[i].compare(kTestFileName2) == 0);
  }
}

}  // namespace wvcdm
