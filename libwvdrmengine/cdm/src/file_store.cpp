// Copyright 2013 Google Inc. All Rights Reserved.
//
// File class - provides a simple android specific file implementation

#include "file_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#include "log.h"

namespace {
const char kCurrentDirectory[] = ".";
const char kParentDirectory[] = "..";
const char kPathDelimiter[] = "/";
const char kWildcard[] = "*";
}  // namespace

namespace wvcdm {

class File::Impl {
 public:
  Impl() : file_(NULL) {}
  Impl(const std::string& file_path) : file_(NULL), file_path_(file_path) {}
  virtual ~Impl() {}

  FILE* file_;
  std::string file_path_;
};

File::File() : impl_(new File::Impl()) {}

File::~File() {
  Close();
  delete impl_;
}

bool File::Open(const std::string& name, int flags) {
  std::string open_flags;

  if (((flags & File::kTruncate) && Exists(name)) ||
      ((flags & File::kCreate) && !Exists(name))) {
    FILE* fp = fopen(name.c_str(), "w+");
    if (fp) {
      fclose(fp);
    }
  }

  if (flags & File::kBinary) {
    open_flags = (flags & File::kReadOnly) ? "rb" : "rb+";
  } else {
    open_flags = (flags & File::kReadOnly) ? "r" : "r+";
  }

  impl_->file_ = fopen(name.c_str(), open_flags.c_str());
  if (!impl_->file_) {
    LOGW("File::Open: fopen failed: %d", errno);
  }
  impl_->file_path_ = name;
  return impl_->file_ != NULL;
}

void File::Close() {
  if (impl_->file_) {
    fclose(impl_->file_);
    impl_->file_ = NULL;
  }
}

ssize_t File::Read(char* buffer, size_t bytes) {
  if (impl_->file_) {
    size_t len = fread(buffer, sizeof(char), bytes, impl_->file_);
    if (len == 0) {
      LOGW("File::Read: fread failed: %d", errno);
    }
    return len;
  }
  LOGW("File::Read: file not open");
  return -1;
}

ssize_t File::Write(const char* buffer, size_t bytes) {
  if (impl_->file_) {
    size_t len = fwrite(buffer, sizeof(char), bytes, impl_->file_);
    if (len == 0) {
      LOGW("File::Write: fwrite failed: %d", errno);
    }
    return len;
  }
  LOGW("File::Write: file not open");
  return -1;
}

bool File::Exists(const std::string& path) {
  struct stat buf;
  int res = stat(path.c_str(), &buf) == 0;
  if (!res) {
    LOGV("File::Exists: stat failed: %d", errno);
  }
  return res;
}

bool File::Remove(const std::string& path) {
  if (IsDirectory(path)) {
    // Handle directory deletion
    DIR* dir;
    if ((dir = opendir(path.c_str())) != NULL) {
      // first remove files and dir within it
      struct dirent* entry;
      while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, kCurrentDirectory) &&
            (strcmp(entry->d_name, kParentDirectory))) {
          std::string path_to_remove = path + kPathDelimiter;
          path_to_remove += entry->d_name;
          if (!Remove(path_to_remove)) {
            closedir(dir);
            return false;
          }
        }
      }
      closedir(dir);
    }
    if (rmdir(path.c_str())) {
      LOGW("File::Remove: rmdir failed: %d", errno);
      return false;
    }
    return true;
  } else {
    size_t wildcard_pos = path.find(kWildcard);
    if (wildcard_pos == std::string::npos) {
      // Handle file deletion
      if (unlink(path.c_str()) && (errno != ENOENT)) {
        LOGW("File::Remove: unlink failed: %d", errno);
        return false;
      }
    } else {
      // Handle wildcard specified file deletion
      size_t delimiter_pos = path.rfind(kPathDelimiter, wildcard_pos);
      if (delimiter_pos == std::string::npos) {
        LOGW("File::Remove: unable to find path delimiter before wildcard");
        return false;
      }

      DIR* dir;
      std::string dir_path = path.substr(0, delimiter_pos);
      if ((dir = opendir(dir_path.c_str())) == NULL) {
        LOGW("File::Remove: directory open failed for wildcard");
        return false;
      }

      struct dirent* entry;
      std::string ext = path.substr(wildcard_pos + 1);

      while ((entry = readdir(dir)) != NULL) {
        size_t filename_len = strlen(entry->d_name);
        if (filename_len > ext.size()) {
          if (strcmp(entry->d_name + filename_len - ext.size(), ext.c_str()) ==
              0) {
            std::string file_path_to_remove =
                dir_path + kPathDelimiter + entry->d_name;
            if (!Remove(file_path_to_remove)) {
              closedir(dir);
              return false;
            }
          }
        }
      }
      closedir(dir);
    }
    return true;
  }
}

bool File::Copy(const std::string& src, const std::string& dest) {
  struct stat stat_buf;
  if (stat(src.c_str(), &stat_buf)) {
    LOGV("File::Copy: file %s does not exist: %d", src.c_str(), errno);
    return false;
  }

  int fd_src = open(src.c_str(), O_RDONLY);
  if (fd_src < 0) {
    LOGV("File::Copy: unable to open file %s: %d", src.c_str(), errno);
    return false;
  }

  int fd_dest = open(dest.c_str(), O_WRONLY|O_CREAT, stat_buf.st_mode);
  if (fd_dest < 0) {
    LOGV("File::Copy: unable to open file %s: %d", dest.c_str(), errno);
    close(fd_src);
    return false;
  }

  off_t offset = 0;
  bool sts = true;
  if (sendfile(fd_dest, fd_src, &offset, stat_buf.st_size) < 0) {
    LOGV("File::Copy: unable to copy %s to %s: %d", src.c_str(), dest.c_str(),
         errno);
    sts = false;
  }

  close(fd_src);
  close(fd_dest);
  return sts;
}

bool File::List(const std::string& path, std::vector<std::string>* files) {
  if (NULL == files) {
    LOGV("File::List: files destination not provided");
    return false;
  }

  if (!Exists(path)) {
    LOGV("File::List: path %s does not exist: %d", path.c_str(), errno);
    return false;
  }

  DIR* dir;
  if ((dir = opendir(path.c_str())) == NULL) {
    LOGW("File::List: unable to open directory %s: %d", path.c_str(), errno);
    return false;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, kCurrentDirectory) &&
        (strcmp(entry->d_name, kParentDirectory))) {
      files->push_back(entry->d_name);
    }
  }
  closedir(dir);

  return true;
}

bool File::CreateDirectory(std::string path) {
  size_t size = path.size();
  if ((size == 1) && (path[0] == kPathDelimiter[0])) return true;

  if (size <= 1) return false;

  if (path.at(size - 1) == kPathDelimiter[0]) {
    --size;
    path.resize(size);
  }

  size_t pos = path.find(kPathDelimiter[0], 1);
  while (pos < size) {
    path.at(pos) = '\0';
    if (mkdir(path.c_str(), 0775) != 0) {
      if (errno != EEXIST) {
        LOGW("File::CreateDirectory: mkdir failed: %d\n", errno);
        return false;
      }
    }
    path.at(pos) = kPathDelimiter[0];
    pos = path.find(kPathDelimiter[0], pos + 1);
  }
  if (mkdir(path.c_str(), 0775) != 0) {
    if (errno != EEXIST) {
      LOGW("File::CreateDirectory: mkdir failed: %d\n", errno);
      return false;
    }
  }
  return true;
}

bool File::IsDirectory(const std::string& path) {
  struct stat buf;
  if (stat(path.c_str(), &buf) == 0)
    return buf.st_mode & S_IFDIR;
  else
    return false;
}

bool File::IsRegularFile(const std::string& path) {
  struct stat buf;
  if (stat(path.c_str(), &buf) == 0)
    return buf.st_mode & S_IFREG;
  else
    return false;
}

ssize_t File::FileSize(const std::string& path) {
  struct stat buf;
  if (stat(path.c_str(), &buf) == 0)
    return buf.st_size;
  else
    return -1;
}

}  // namespace wvcdm
