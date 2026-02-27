// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>  // Must come first

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000C  // For SHGetKnownFolderPath in ShlObj_core.h in ShlObj.h
#endif

#include <KnownFolders.h>
#include <ShlObj.h>
#include <libloaderapi.h>
#include <string.h>  // _wcsnicmp
#include <strsafe.h>
#include <locale>
#else
#include <dlfcn.h>
#endif  // defined(_WIN32)

#include <toml++/toml.hpp>
#include "arrow-adbc/adbc.h"
#include "arrow-adbc/adbc_driver_manager.h"
#include "adbc_driver_manager_internal.h"
#include "current_arch.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <regex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std::string_literals;  // NOLINT [build/namespaces]

ADBC_EXPORT
std::vector<std::filesystem::path> InternalAdbcParsePath(const std::string_view path);
ADBC_EXPORT
std::filesystem::path InternalAdbcUserConfigDir();
#if !defined(_WIN32)
ADBC_EXPORT
std::filesystem::path InternalAdbcSystemConfigDir();
#endif  // !defined(_WIN32)

struct ParseDriverUriResult {
  std::string_view driver;
  std::optional<std::string_view> uri;
  std::optional<std::string_view> profile;
};

ADBC_EXPORT
std::optional<ParseDriverUriResult> InternalAdbcParseDriverUri(std::string_view str);

namespace {

/// \brief Where a search path came from (for error reporting)
enum class SearchPathSource {
  kEnv,
  kUser,
  kRegistry,
  kSystem,
  kAdditional,
  kConda,
  kUnset,
  kDoesNotExist,
  kDisabledAtCompileTime,
  kDisabledAtRunTime,
  kOtherError,
};

enum class SearchPathType {
  kManifest,
  kProfile,
};

using SearchPaths = std::vector<std::pair<SearchPathSource, std::filesystem::path>>;

void AddSearchPathsToError(const SearchPaths& search_paths, const SearchPathType& type,
                           std::string& error_message) {
  if (!search_paths.empty()) {
    error_message += "\nAlso searched these paths for";
    if (type == SearchPathType::kManifest) {
      error_message += " manifests:";
    } else if (type == SearchPathType::kProfile) {
      error_message += " profiles:";
    }

    for (const auto& [source, path] : search_paths) {
      error_message += "\n\t";
      switch (source) {
        case SearchPathSource::kEnv:
          if (type == SearchPathType::kManifest) {
            error_message += "ADBC_DRIVER_PATH: ";
          } else if (type == SearchPathType::kProfile) {
            error_message += "ADBC_PROFILE_PATH: ";
          }
          break;
        case SearchPathSource::kUser:
          error_message += "user config dir: ";
          break;
        case SearchPathSource::kRegistry:
          error_message += "Registry: ";
          break;
        case SearchPathSource::kSystem:
          error_message += "system config dir: ";
          break;
        case SearchPathSource::kAdditional:
          error_message += "additional search path: ";
          break;
        case SearchPathSource::kConda:
          error_message += "Conda prefix: ";
          break;
        case SearchPathSource::kUnset:
          error_message += "not set: ";
          break;
        case SearchPathSource::kDoesNotExist:
          error_message += "does not exist: ";
          break;
        case SearchPathSource::kDisabledAtCompileTime:
          error_message += "not enabled at build time: ";
          break;
        case SearchPathSource::kDisabledAtRunTime:
          error_message += "not enabled at run time: ";
          break;
        case SearchPathSource::kOtherError:
          // Don't add any prefix
          break;
      }
      error_message += path.string();
    }
  }
}

// Generate a note for the error message if the library name has potentially
// non-printable (or really non-ASCII-printable-range) characters.  Oblivious
// to Unicode and locales.
std::string CheckNonPrintableLibraryName(const std::string& name) {
  // We could use std::isprint, but that requires locales; prefer a
  // simpler check for out-of-ASCII-range.
  bool has_non_printable = std::any_of(name.begin(), name.end(), [](char c) {
    int v = static_cast<int>(c);
    return v < 32 || v > 127;
  });
  if (!has_non_printable) return "";

  std::string error_message = "Note: driver name may have non-printable characters: `";
  // TODO(lidavidm): we can simplify with C++20 <format>
  for (char c : name) {
    int v = static_cast<int>(c);
    if (v < 32 || v > 127) {
      error_message += "\\x";
      char buf[3];
      std::snprintf(buf, sizeof(buf), "%02x", v & 0xFF);
      error_message += buf;
    } else {
      error_message += c;
    }
  }
  error_message += "`";
  return error_message;
}

// Platform-specific helpers

#if defined(_WIN32)
/// Append a description of the Windows error to the buffer.
void GetWinError(std::string* buffer) {
  DWORD rc = GetLastError();
  LPVOID message;

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                /*lpSource=*/nullptr, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPSTR>(&message), /*nSize=*/0, /*Arguments=*/nullptr);

  (*buffer) += '(';
  (*buffer) += std::to_string(rc);
  (*buffer) += ") ";
  (*buffer) += reinterpret_cast<char*>(message);
  LocalFree(message);
}

#endif  // defined(_WIN32)

// Error handling

void ReleaseError(struct AdbcError* error) {
  if (error) {
    if (error->message) delete[] error->message;
    error->message = nullptr;
    error->release = nullptr;
  }
}

void SetError(struct AdbcError* error, const std::string& message) {
  static const std::string kPrefix = "[Driver Manager] ";

  if (!error) return;
  if (error->release) error->release(error);

  // Prepend a string to identify driver manager errors
  error->message = new char[kPrefix.size() + message.size() + 1];
  kPrefix.copy(error->message, kPrefix.size());
  message.copy(error->message + kPrefix.size(), message.size());
  error->message[kPrefix.size() + message.size()] = '\0';
  error->release = ReleaseError;
}

void AppendError(struct AdbcError* error, const std::string& message) {
  if (!error) return;
  if (!error->release || !error->message) {
    SetError(error, message);
    return;
  }

  size_t original_length = std::strlen(error->message);
  size_t combined_length = original_length + 1 + message.size() + 1;
  char* new_message = new char[combined_length];
  std::ignore = std::snprintf(new_message, combined_length, "%s\n%s", error->message,
                              message.c_str());

  error->release(error);
  error->message = new_message;
  error->release = ReleaseError;
}

// Copies src_error into error and releases src_error
void SetError(struct AdbcError* error, struct AdbcError* src_error) {
  if (!error) return;
  if (error->release) error->release(error);

  if (src_error->message) {
    size_t message_size = strlen(src_error->message);
    error->message = new char[message_size + 1];  // +1 to include null
    std::memcpy(error->message, src_error->message, message_size);
    error->message[message_size] = '\0';
  } else {
    error->message = nullptr;
  }

  error->release = ReleaseError;
  if (src_error->release) {
    src_error->release(src_error);
  }
}

struct OwnedError {
  struct AdbcError error = ADBC_ERROR_INIT;

  ~OwnedError() {
    if (error.release) {
      error.release(&error);
    }
  }
};

#ifdef _WIN32
using char_type = wchar_t;
using string_type = std::wstring;

std::string Utf8Encode(const std::wstring& wstr) {
  if (wstr.empty()) return std::string();
  int size_needed = WideCharToMultiByte(
      CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
  std::string str_to(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
                      str_to.data(), size_needed, NULL, NULL);
  return str_to;
}

std::wstring Utf8Decode(const std::string& str) {
  if (str.empty()) return std::wstring();
  int size_needed =
      MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
  std::wstring wstr_to(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
                      wstr_to.data(), size_needed);
  return wstr_to;
}

#else
using char_type = char;
using string_type = std::string;
#endif  // _WIN32

/// \brief The location and entrypoint of a resolved driver.
struct DriverInfo {
  std::string manifest_file;
  int64_t manifest_version = 0;
  std::string driver_name;
  std::filesystem::path lib_path;
  std::string entrypoint;

  std::string version;
  std::string source;
};

#ifdef _WIN32
class RegistryKey {
 public:
  RegistryKey(HKEY root, const std::wstring_view subkey) noexcept
      : root_(root), key_(nullptr) {
    status_ = RegOpenKeyExW(root_, subkey.data(), 0, KEY_READ, &key_);
  }

  ~RegistryKey() {
    if (is_open() && key_ != nullptr) {
      RegCloseKey(key_);
      key_ = nullptr;
      status_ = ERROR_REGISTRY_IO_FAILED;
    }
  }

  HKEY key() const { return key_; }
  bool is_open() const { return status_ == ERROR_SUCCESS; }
  LSTATUS status() const { return status_; }

  std::wstring GetString(const std::wstring& name, std::wstring default_value) {
    if (!is_open()) return default_value;

    DWORD type = REG_SZ;
    DWORD size = 0;
    auto result = RegQueryValueExW(key_, name.data(), nullptr, &type, nullptr, &size);
    if (result != ERROR_SUCCESS) return default_value;
    if (type != REG_SZ) return default_value;

    std::wstring value(size, '\0');
    result = RegQueryValueExW(key_, name.data(), nullptr, &type,
                              reinterpret_cast<LPBYTE>(value.data()), &size);
    if (result != ERROR_SUCCESS) return default_value;
    return value;
  }

  int32_t GetInt(const std::wstring& name, const int32_t default_value) {
    if (!is_open()) return default_value;

    DWORD dwValue;
    DWORD dataSize = sizeof(dwValue);
    DWORD valueType;
    auto result = RegQueryValueExW(key_, name.data(), nullptr, &valueType,
                                   (LPBYTE)&dwValue, &dataSize);
    if (result != ERROR_SUCCESS) return default_value;
    if (valueType != REG_DWORD) return default_value;
    return static_cast<int32_t>(dwValue);
  }

 private:
  HKEY root_;
  HKEY key_;
  LSTATUS status_;
};
#endif  // _WIN32

#define CHECK_STATUS(EXPR)                                \
  if (auto _status = (EXPR); _status != ADBC_STATUS_OK) { \
    return _status;                                       \
  }

SearchPaths GetEnvPaths(const char_type* env_var) {
#ifdef _WIN32
  DWORD required_size = GetEnvironmentVariableW(env_var, NULL, 0);
  if (required_size == 0) {
    return {};
  }

  std::wstring path_var;
  path_var.resize(required_size);
  DWORD actual_size = GetEnvironmentVariableW(env_var, path_var.data(), required_size);
  // Remove null terminator
  path_var.resize(actual_size);
  auto path = Utf8Encode(path_var);
#else
  const char* path_var = std::getenv(env_var);
  if (!path_var) {
    return {};
  }
  std::string path(path_var);
#endif  // _WIN32
  SearchPaths paths;
  for (auto parsed_path : InternalAdbcParsePath(path)) {
    paths.emplace_back(SearchPathSource::kEnv, parsed_path);
  }
  return paths;
}

#ifdef _WIN32
static const wchar_t* kAdbcDriverPath = L"ADBC_DRIVER_PATH";
static const wchar_t* kAdbcProfilePath = L"ADBC_PROFILE_PATH";
#else
static const char* kAdbcDriverPath = "ADBC_DRIVER_PATH";
static const char* kAdbcProfilePath = "ADBC_PROFILE_PATH";
#endif  // _WIN32

SearchPaths GetSearchPaths(const AdbcLoadFlags levels) {
  SearchPaths paths;
  if (levels & ADBC_LOAD_FLAG_SEARCH_ENV) {
    // Check the ADBC_DRIVER_PATH environment variable
    paths = GetEnvPaths(kAdbcDriverPath);
  }

  if (levels & ADBC_LOAD_FLAG_SEARCH_USER) {
    // Check the user configuration directory
    std::filesystem::path user_config_dir = InternalAdbcUserConfigDir();
    if (!user_config_dir.empty() && std::filesystem::exists(user_config_dir)) {
      paths.emplace_back(SearchPathSource::kUser, std::move(user_config_dir));
    } else {
      paths.emplace_back(SearchPathSource::kDoesNotExist, std::move(user_config_dir));
    }
  }

  if (levels & ADBC_LOAD_FLAG_SEARCH_SYSTEM) {
    // System level behavior for Windows is to search the registry keys so we
    // only need to check for macOS and fall back to Unix-like behavior as long
    // as we're not on Windows
#if !defined(_WIN32)
    const std::filesystem::path system_config_dir = InternalAdbcSystemConfigDir();
    if (std::filesystem::exists(system_config_dir)) {
      paths.emplace_back(SearchPathSource::kSystem, std::move(system_config_dir));
    } else {
      paths.emplace_back(SearchPathSource::kDoesNotExist, std::move(system_config_dir));
    }
#endif  // !defined(_WIN32)
  }

  return paths;
}

bool HasExtension(const std::filesystem::path& path, const std::string& ext) {
#ifdef _WIN32
  auto wext = Utf8Decode(ext);
  auto path_ext = path.extension().native();
  return path_ext.size() == wext.size() &&
         _wcsnicmp(path_ext.data(), wext.data(), wext.size()) == 0;
#else
  return path.extension() == ext;
#endif  // _WIN32
}

/// A driver DLL.
struct ManagedLibrary {
  ManagedLibrary() : handle(nullptr) {}
  ManagedLibrary(ManagedLibrary&& other) : handle(other.handle) {
    other.handle = nullptr;
  }
  ManagedLibrary(const ManagedLibrary&) = delete;
  ManagedLibrary& operator=(const ManagedLibrary&) = delete;
  ManagedLibrary& operator=(ManagedLibrary&& other) noexcept {
    this->handle = other.handle;
    other.handle = nullptr;
    return *this;
  }

  ~ManagedLibrary() { Release(); }

  void Release() {
    // TODO(apache/arrow-adbc#204): causes tests to segfault.  Need to
    // refcount the driver DLL; also, errors may retain a reference to
    // release() from the DLL - how to handle this?  It's unlikely we can
    // actually do this - in general shared libraries are not safe to unload.
  }

  /// \brief Resolve the driver name to a concrete location.
  AdbcStatusCode GetDriverInfo(
      const std::string_view driver_name, const AdbcLoadFlags load_options,
      const std::vector<std::filesystem::path>& additional_search_paths, DriverInfo& info,
      struct AdbcError* error) {
    if (driver_name.empty()) {
      SetError(error, "Driver name is empty");
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

    // First try to treat the given driver name as a path to a manifest or shared library
    std::filesystem::path driver_path(driver_name);
    const bool allow_relative_paths = load_options & ADBC_LOAD_FLAG_ALLOW_RELATIVE_PATHS;
    if (driver_path.has_extension()) {
      if (driver_path.is_relative() && !allow_relative_paths) {
        SetError(error, "Driver path is relative and relative paths are not allowed");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      if (HasExtension(driver_path, ".toml")) {
        // if the extension is .toml, attempt to load the manifest
        // erroring if we fail

        auto status = LoadDriverManifest(driver_path, info, error);
        if (status == ADBC_STATUS_OK) {
          return Load(info.lib_path.native(), {}, error);
        }
        return status;
      }

      // if the extension is not .toml, then just try to load the provided
      // path as if it was an absolute path to a driver library
      info.lib_path = driver_path;
      return Load(driver_path.native(), {}, error);
    }

    if (driver_path.is_absolute()) {
      // if we have an absolute path without an extension, first see if there's a
      // toml file with the same name.
      driver_path.replace_extension(".toml");
      if (std::filesystem::exists(driver_path)) {
        auto status = LoadDriverManifest(driver_path, info, error);
        if (status == ADBC_STATUS_OK) {
          return Load(info.lib_path.native(), {}, error);
        }
      }

      driver_path.replace_extension("");
      // otherwise just try to load the provided path as if it was an absolute path
      info.lib_path = driver_path;
      return Load(driver_path.native(), {}, error);
    }

    if (driver_path.has_extension()) {
      if (driver_path.is_relative() && !allow_relative_paths) {
        SetError(error, "Driver path is relative and relative paths are not allowed");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

#if defined(_WIN32)
      static const std::string kPlatformLibrarySuffix = ".dll";
#elif defined(__APPLE__)
      static const std::string kPlatformLibrarySuffix = ".dylib";
#else
      static const std::string kPlatformLibrarySuffix = ".so";
#endif  // defined(_WIN32)
      if (HasExtension(driver_path, kPlatformLibrarySuffix)) {
        info.lib_path = driver_path;
        return Load(driver_path.native(), {}, error);
      }

      SetError(error, "Driver name has unrecognized extension: " +
                          driver_path.extension().string());
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

    // not an absolute path, no extension. Let's search the configured paths
    // based on the options
    // FindDriver will set info.lib_path
    // XXX(lidavidm): the control flow in this call chain is excessively
    // convoluted and it's hard to determine if DriverInfo is fully
    // initialized or not in all non-error paths
    return FindDriver(driver_path, load_options, additional_search_paths, info, error);
  }

  /// \return ADBC_STATUS_NOT_FOUND if the driver shared library could not be
  ///   found (via dlopen) or if a manifest was found but did not contain a
  ///   path for the current platform, ADBC_STATUS_INVALID_ARGUMENT if a
  ///   manifest was found but could not be parsed, ADBC_STATUS_OK otherwise
  ///
  /// May modify search_paths to add error info
  AdbcStatusCode SearchPathsForDriver(const std::filesystem::path& driver_path,
                                      SearchPaths& search_paths, DriverInfo& info,
                                      struct AdbcError* error) {
    SearchPaths extra_debug_info;
    for (const auto& [source, search_path] : search_paths) {
      if (source == SearchPathSource::kRegistry || source == SearchPathSource::kUnset ||
          source == SearchPathSource::kDoesNotExist ||
          source == SearchPathSource::kDisabledAtCompileTime ||
          source == SearchPathSource::kDisabledAtRunTime ||
          source == SearchPathSource::kOtherError) {
        continue;
      }
      std::filesystem::path full_path = search_path / driver_path;

      // check for toml first, then dll
      full_path.replace_extension(".toml");
      if (std::filesystem::exists(full_path)) {
        OwnedError intermediate_error;

        auto status = LoadDriverManifest(full_path, info, &intermediate_error.error);
        if (status == ADBC_STATUS_OK) {
          // Don't pass attempted_paths here; we'll generate the error at a higher level
          status = Load(info.lib_path.native(), {}, &intermediate_error.error);
          if (status == ADBC_STATUS_OK) {
            return status;
          }
          std::string message = "found ";
          message += full_path.string();
          if (intermediate_error.error.message) {
            message += " but: ";
            message += intermediate_error.error.message;
          } else {
            message += " could not load the driver it specified";
          }
          extra_debug_info.emplace_back(SearchPathSource::kOtherError,
                                        std::move(message));
          search_paths.insert(search_paths.end(), extra_debug_info.begin(),
                              extra_debug_info.end());
          return status;
        } else if (status == ADBC_STATUS_INVALID_ARGUMENT) {
          // The manifest was invalid. Don't ignore that!
          search_paths.insert(search_paths.end(), extra_debug_info.begin(),
                              extra_debug_info.end());
          if (intermediate_error.error.message) {
            std::string error_message = intermediate_error.error.message;
            AddSearchPathsToError(search_paths, SearchPathType::kManifest, error_message);
            SetError(error, std::move(error_message));
          }
          return status;
        }
        // Should be NOT_FOUND otherwise
        std::string message = "found ";
        message += full_path.string();
        if (intermediate_error.error.message) {
          message += " but: ";
          message += intermediate_error.error.message;
        } else {
          message += " which did not define a driver for this platform";
        }

        extra_debug_info.emplace_back(SearchPathSource::kOtherError, std::move(message));
      }

      // remove the .toml extension; Load will add the DLL/SO/DYLIB suffix
      full_path.replace_extension("");
      // Don't pass error here - it'll be suppressed anyways
      auto status = Load(full_path.native(), {}, nullptr);
      if (status == ADBC_STATUS_OK) {
        info.lib_path = full_path;
        return status;
      }
    }

    search_paths.insert(search_paths.end(), extra_debug_info.begin(),
                        extra_debug_info.end());
    return ADBC_STATUS_NOT_FOUND;
  }

  AdbcStatusCode FindDriver(
      const std::filesystem::path& driver_path, const AdbcLoadFlags load_options,
      const std::vector<std::filesystem::path>& additional_search_paths, DriverInfo& info,
      struct AdbcError* error) {
    if (driver_path.empty()) {
      SetError(error, "Driver path is empty");
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

    SearchPaths search_paths;
    {
      // First search the paths in the env var `ADBC_DRIVER_PATH`.
      // Then search the runtime application-defined additional search paths.
      search_paths = GetSearchPaths(load_options & ADBC_LOAD_FLAG_SEARCH_ENV);
      if (!(load_options & ADBC_LOAD_FLAG_SEARCH_ENV)) {
        search_paths.emplace_back(SearchPathSource::kDisabledAtRunTime,
                                  "ADBC_DRIVER_PATH (enable ADBC_LOAD_FLAG_SEARCH_ENV)");
      } else if (search_paths.empty()) {
        search_paths.emplace_back(SearchPathSource::kUnset, "ADBC_DRIVER_PATH");
      }
      for (const auto& path : additional_search_paths) {
        search_paths.emplace_back(SearchPathSource::kAdditional, path);
      }

#if ADBC_CONDA_BUILD
      // Then, if this is a conda build, search in the conda environment if
      // it is activated.
      if (load_options & ADBC_LOAD_FLAG_SEARCH_ENV) {
#ifdef _WIN32
        const wchar_t* conda_name = L"CONDA_PREFIX";
#else
        const char* conda_name = "CONDA_PREFIX";
#endif  // _WIN32
        auto venv = GetEnvPaths(conda_name);
        if (!venv.empty()) {
          for (const auto& [_, venv_path] : venv) {
            search_paths.emplace_back(SearchPathSource::kConda,
                                      venv_path / "etc" / "adbc" / "drivers");
          }
        }
      } else {
        search_paths.emplace_back(SearchPathSource::kDisabledAtRunTime,
                                  "Conda prefix (enable ADBC_LOAD_FLAG_SEARCH_ENV)");
      }
#else
      if (load_options & ADBC_LOAD_FLAG_SEARCH_ENV) {
        search_paths.emplace_back(SearchPathSource::kDisabledAtCompileTime,
                                  "Conda prefix");
      }
#endif  // ADBC_CONDA_BUILD

      auto status = SearchPathsForDriver(driver_path, search_paths, info, error);
      if (status != ADBC_STATUS_NOT_FOUND) {
        // If NOT_FOUND, then keep searching; if OK or INVALID_ARGUMENT, stop
        return status;
      }
    }

    // We searched environment paths and additional search paths (if they
    // exist), so now search the rest.
#ifdef _WIN32
    // On Windows, check registry keys, not just search paths.
    if (load_options & ADBC_LOAD_FLAG_SEARCH_USER) {
      // Check the user registry for the driver.
      auto status =
          LoadDriverFromRegistry(HKEY_CURRENT_USER, driver_path.native(), info, error);
      if (status == ADBC_STATUS_OK) {
        return Load(info.lib_path.native(), {}, error);
      }
      if (error && error->message) {
        std::string message = "HKEY_CURRENT_USER\\"s;
        message += error->message;
        search_paths.emplace_back(SearchPathSource::kRegistry, std::move(message));
      } else {
        search_paths.emplace_back(SearchPathSource::kRegistry,
                                  "not found in HKEY_CURRENT_USER");
      }

      auto user_paths = GetSearchPaths(ADBC_LOAD_FLAG_SEARCH_USER);
      status = SearchPathsForDriver(driver_path, user_paths, info, error);
      if (status != ADBC_STATUS_NOT_FOUND) {
        return status;
      }
      search_paths.insert(search_paths.end(), user_paths.begin(), user_paths.end());
    } else {
      search_paths.emplace_back(SearchPathSource::kDisabledAtRunTime,
                                "HKEY_CURRENT_USER (enable ADBC_LOAD_FLAG_SEARCH_USER)");
    }

    if (load_options & ADBC_LOAD_FLAG_SEARCH_SYSTEM) {
      // Check the system registry for the driver.
      auto status =
          LoadDriverFromRegistry(HKEY_LOCAL_MACHINE, driver_path.native(), info, error);
      if (status == ADBC_STATUS_OK) {
        return Load(info.lib_path.native(), {}, error);
      }
      if (error && error->message) {
        std::string message = "HKEY_LOCAL_MACHINE\\"s;
        message += error->message;
        search_paths.emplace_back(SearchPathSource::kRegistry, std::move(message));
      } else {
        search_paths.emplace_back(SearchPathSource::kRegistry,
                                  "not found in HKEY_LOCAL_MACHINE");
      }

      auto system_paths = GetSearchPaths(ADBC_LOAD_FLAG_SEARCH_SYSTEM);
      status = SearchPathsForDriver(driver_path, system_paths, info, error);
      if (status != ADBC_STATUS_NOT_FOUND) {
        return status;
      }
      search_paths.insert(search_paths.end(), system_paths.begin(), system_paths.end());
    } else {
      search_paths.emplace_back(
          SearchPathSource::kDisabledAtRunTime,
          "HKEY_LOCAL_MACHINE (enable ADBC_LOAD_FLAG_SEARCH_SYSTEM)");
    }

    info.lib_path = driver_path;
    return Load(driver_path.native(), search_paths, error);
#else
    // Otherwise, search the configured paths.
    SearchPaths more_search_paths =
        GetSearchPaths(load_options & ~ADBC_LOAD_FLAG_SEARCH_ENV);
    auto status = SearchPathsForDriver(driver_path, more_search_paths, info, error);
    if (status == ADBC_STATUS_NOT_FOUND) {
      if (!(load_options & ADBC_LOAD_FLAG_SEARCH_USER)) {
        std::filesystem::path user_config_dir = InternalAdbcUserConfigDir();
        std::string message = "user config dir ";
        message += user_config_dir.string();
        message += " (enable ADBC_LOAD_FLAG_SEARCH_USER)";
        more_search_paths.emplace_back(SearchPathSource::kDisabledAtRunTime,
                                       std::move(message));
      }
      // Windows searches registry keys, so this only applies to other OSes
#if !defined(_WIN32)
      if (!(load_options & ADBC_LOAD_FLAG_SEARCH_SYSTEM)) {
        std::filesystem::path system_config_dir = InternalAdbcSystemConfigDir();
        std::string message = "system config dir ";
        message += system_config_dir.string();
        message += " (enable ADBC_LOAD_FLAG_SEARCH_SYSTEM)";
        more_search_paths.emplace_back(SearchPathSource::kDisabledAtRunTime,
                                       std::move(message));
      }
#endif  // !defined(_WIN32)

      // If we reach here, we didn't find the driver in any of the paths
      // so let's just attempt to load it as default behavior.
      search_paths.insert(search_paths.end(), more_search_paths.begin(),
                          more_search_paths.end());
      info.lib_path = driver_path;
      return Load(driver_path.native(), search_paths, error);
    }
    return status;
#endif  // _WIN32
  }

  /// \return ADBC_STATUS_NOT_FOUND if the driver shared library could not be
  ///   found, ADBC_STATUS_OK otherwise
  AdbcStatusCode Load(const string_type& library, const SearchPaths& attempted_paths,
                      struct AdbcError* error) {
    std::string error_message;
#if defined(_WIN32)
    HMODULE handle = LoadLibraryExW(library.c_str(), NULL, 0);
    if (!handle) {
      error_message = "Could not load `";
      error_message += Utf8Encode(library);
      error_message += "`: LoadLibraryExW() failed: ";
      GetWinError(&error_message);

      std::wstring full_driver_name = library;
      full_driver_name += L".dll";
      handle = LoadLibraryExW(full_driver_name.c_str(), NULL, 0);
      if (!handle) {
        error_message += '\n';
        error_message += Utf8Encode(full_driver_name);
        error_message += ": LoadLibraryExW() failed: ";
        GetWinError(&error_message);
      }
    }
    if (!handle) {
      std::string name = Utf8Encode(library);
      std::string message = CheckNonPrintableLibraryName(name);
      if (!message.empty()) {
        error_message += "\n";
        error_message += message;
      }
      AddSearchPathsToError(attempted_paths, SearchPathType::kManifest, error_message);
      SetError(error, error_message);
      return ADBC_STATUS_NOT_FOUND;
    } else {
      this->handle = handle;
    }
#else
    static const std::string kPlatformLibraryPrefix = "lib";
#if defined(__APPLE__)
    static const std::string kPlatformLibrarySuffix = ".dylib";
#else
    static const std::string kPlatformLibrarySuffix = ".so";
#endif  // defined(__APPLE__)

    void* handle = dlopen(library.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
      error_message = "Could not load `";
      error_message += library;
      error_message += "`: dlopen() failed: ";
      error_message += dlerror();

      // If applicable, append the shared library prefix/extension and
      // try again (this way you don't have to hardcode driver names by
      // platform in the application)
      const std::string driver_str = library;

      std::string full_driver_name;
      if (driver_str.size() < kPlatformLibraryPrefix.size() ||
          driver_str.compare(0, kPlatformLibraryPrefix.size(), kPlatformLibraryPrefix) !=
              0) {
        full_driver_name += kPlatformLibraryPrefix;
      }
      full_driver_name += library;
      if (driver_str.size() < kPlatformLibrarySuffix.size() ||
          driver_str.compare(full_driver_name.size() - kPlatformLibrarySuffix.size(),
                             kPlatformLibrarySuffix.size(),
                             kPlatformLibrarySuffix) != 0) {
        full_driver_name += kPlatformLibrarySuffix;
      }
      handle = dlopen(full_driver_name.c_str(), RTLD_NOW | RTLD_LOCAL);
      if (!handle) {
        error_message += "\ndlopen() failed: ";
        error_message += dlerror();
      }
    }
    if (handle) {
      this->handle = handle;
    } else {
      std::string message = CheckNonPrintableLibraryName(library);
      if (!message.empty()) {
        error_message += "\n";
        error_message += message;
      }
      AddSearchPathsToError(attempted_paths, SearchPathType::kManifest, error_message);
      SetError(error, error_message);
      return ADBC_STATUS_NOT_FOUND;
    }
#endif  // defined(_WIN32)
    return ADBC_STATUS_OK;
  }

  AdbcStatusCode Lookup(const char* name, void** func, struct AdbcError* error) {
#if defined(_WIN32)
    void* load_handle = reinterpret_cast<void*>(GetProcAddress(handle, name));
    if (!load_handle) {
      std::string message = "GetProcAddress(";
      message += name;
      message += ") failed: ";
      GetWinError(&message);
      AppendError(error, message);
      return ADBC_STATUS_INTERNAL;
    }
#else
    void* load_handle = dlsym(handle, name);
    if (!load_handle) {
      std::string message = "dlsym(";
      message += name;
      message += ") failed: ";
      message += dlerror();
      AppendError(error, message);
      return ADBC_STATUS_INTERNAL;
    }
#endif  // defined(_WIN32)
    *func = load_handle;
    return ADBC_STATUS_OK;
  }

#if defined(_WIN32)
  // The loaded DLL
  HMODULE handle;
#else
  void* handle;
#endif  // defined(_WIN32)
};

struct FilesystemProfile {
  std::filesystem::path path;
  std::string driver;
  std::unordered_map<std::string, std::string> options;
  std::unordered_map<std::string, int64_t> int_options;
  std::unordered_map<std::string, double> double_options;

  std::vector<const char*> options_keys;
  std::vector<const char*> options_values;

  std::vector<const char*> int_option_keys;
  std::vector<int64_t> int_option_values;

  std::vector<const char*> double_option_keys;
  std::vector<double> double_option_values;

  void PopulateConnectionProfile(struct AdbcConnectionProfile* out) {
    options_keys.reserve(options.size());
    options_values.reserve(options.size());
    for (const auto& [key, value] : options) {
      options_keys.push_back(key.c_str());
      options_values.push_back(value.c_str());
    }

    int_option_keys.reserve(int_options.size());
    int_option_values.reserve(int_options.size());
    for (const auto& [key, value] : int_options) {
      int_option_keys.push_back(key.c_str());
      int_option_values.push_back(value);
    }

    double_option_keys.reserve(double_options.size());
    double_option_values.reserve(double_options.size());
    for (const auto& [key, value] : double_options) {
      double_option_keys.push_back(key.c_str());
      double_option_values.push_back(value);
    }

    out->private_data = new FilesystemProfile(std::move(*this));
    out->release = [](AdbcConnectionProfile* profile) {
      if (!profile || !profile->private_data) {
        return;
      }

      delete static_cast<FilesystemProfile*>(profile->private_data);
      profile->private_data = nullptr;
      profile->release = nullptr;
    };

    out->GetDriverName = [](AdbcConnectionProfile* profile, const char** out,
                            AdbcDriverInitFunc* init_func,
                            struct AdbcError* error) -> AdbcStatusCode {
      if (!profile || !profile->private_data) {
        SetError(error, "Invalid connection profile");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      auto* fs_profile = static_cast<FilesystemProfile*>(profile->private_data);
      *out = fs_profile->driver.c_str();
      *init_func = nullptr;
      return ADBC_STATUS_OK;
    };

    out->GetOptions = [](AdbcConnectionProfile* profile, const char*** keys,
                         const char*** values, size_t* num_options,
                         struct AdbcError* error) -> AdbcStatusCode {
      if (!profile || !profile->private_data) {
        SetError(error, "Invalid connection profile");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      if (!keys || !values || !num_options) {
        SetError(error, "Output parameters cannot be null");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      auto* fs_profile = static_cast<FilesystemProfile*>(profile->private_data);
      *num_options = fs_profile->options.size();
      *keys = fs_profile->options_keys.data();
      *values = fs_profile->options_values.data();
      return ADBC_STATUS_OK;
    };

    out->GetIntOptions = [](AdbcConnectionProfile* profile, const char*** keys,
                            const int64_t** values, size_t* num_options,
                            struct AdbcError* error) -> AdbcStatusCode {
      if (!profile || !profile->private_data) {
        SetError(error, "Invalid connection profile");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      if (!keys || !values || !num_options) {
        SetError(error, "Output parameters cannot be null");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      auto* fs_profile = static_cast<FilesystemProfile*>(profile->private_data);
      *num_options = fs_profile->int_options.size();
      *keys = fs_profile->int_option_keys.data();
      *values = fs_profile->int_option_values.data();
      return ADBC_STATUS_OK;
    };

    out->GetDoubleOptions = [](AdbcConnectionProfile* profile, const char*** keys,
                               const double** values, size_t* num_options,
                               struct AdbcError* error) -> AdbcStatusCode {
      if (!profile || !profile->private_data) {
        SetError(error, "Invalid connection profile");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      if (!keys || !values || !num_options) {
        SetError(error, "Output parameters cannot be null");
        return ADBC_STATUS_INVALID_ARGUMENT;
      }

      auto* fs_profile = static_cast<FilesystemProfile*>(profile->private_data);
      *num_options = fs_profile->double_options.size();
      *keys = fs_profile->double_option_keys.data();
      *values = fs_profile->double_option_values.data();
      return ADBC_STATUS_OK;
    };
  }
};

struct ProfileVisitor {
  FilesystemProfile& profile;
  const std::filesystem::path& profile_path;
  struct AdbcError* error;

  bool VisitTable(const std::string& prefix, toml::table& table) {
    for (const auto& [key, value] : table) {
      if (auto* str = value.as_string()) {
        profile.options[prefix + key.data()] = str->get();
      } else if (auto* int_val = value.as_integer()) {
        profile.int_options[prefix + key.data()] = int_val->get();
      } else if (auto* double_val = value.as_floating_point()) {
        profile.double_options[prefix + key.data()] = double_val->get();
      } else if (auto* bool_val = value.as_boolean()) {
        profile.options[prefix + key.data()] = bool_val->get() ? "true" : "false";
      } else if (value.is_table()) {
        if (!VisitTable(prefix + key.data() + ".", *value.as_table())) {
          return false;
        }
      } else {
        std::string message = "Unsupported value type for key '" +
                              std::string(key.str()) + "' in profile '" +
                              profile_path.string() + "'";
        SetError(error, std::move(message));
        return false;
      }
    }
    return !error->message;
  }
};

SearchPaths GetProfileSearchPaths(const char* additional_search_path_list) {
  SearchPaths search_paths;
  {
    std::vector<std::filesystem::path> additional_paths;
    if (additional_search_path_list) {
      additional_paths = InternalAdbcParsePath(additional_search_path_list);
    }

    for (const auto& path : additional_paths) {
      search_paths.emplace_back(SearchPathSource::kAdditional, path);
    }
  }

  {
    auto env_paths = GetEnvPaths(kAdbcProfilePath);
    search_paths.insert(search_paths.end(), env_paths.begin(), env_paths.end());
  }

#if ADBC_CONDA_BUILD
#ifdef _WIN32
  const wchar_t* conda_name = L"CONDA_PREFIX";
#else
  const char* conda_name = "CONDA_PREFIX";
#endif  // _WIN32

  auto venv = GetEnvPaths(conda_name);
  for (const auto& [_, venv_path] : venv) {
    search_paths.emplace_back(SearchPathSource::kConda,
                              venv_path / "etc" / "adbc" / "profiles");
  }
#else
  search_paths.emplace_back(SearchPathSource::kDisabledAtCompileTime, "Conda prefix");
#endif  // ADBC_CONDA_BUILD

#ifdef _WIN32
  const wchar_t* profiles_dir = L"Profiles";
#elif defined(__APPLE__)
  const char* profiles_dir = "Profiles";
#else
  const char* profiles_dir = "profiles";
#endif  // defined(_WIN32)

  auto user_dir = InternalAdbcUserConfigDir().parent_path() / profiles_dir;
  search_paths.emplace_back(SearchPathSource::kUser, user_dir);
  return search_paths;
}

/// Hold the driver DLL and the driver release callback in the driver struct.
struct ManagerDriverState {
  // The original release callback
  AdbcStatusCode (*driver_release)(struct AdbcDriver* driver, struct AdbcError* error);

  ManagedLibrary handle;
};

/// Unload the driver DLL.
AdbcStatusCode ReleaseDriver(struct AdbcDriver* driver, struct AdbcError* error) {
  AdbcStatusCode status = ADBC_STATUS_OK;

  if (!driver->private_manager) return status;
  ManagerDriverState* state =
      reinterpret_cast<ManagerDriverState*>(driver->private_manager);

  if (state->driver_release) {
    status = state->driver_release(driver, error);
  }
  state->handle.Release();

  driver->private_manager = nullptr;
  delete state;
  return status;
}

// ArrowArrayStream wrapper to support AdbcErrorFromArrayStream

struct ErrorArrayStream {
  struct ArrowArrayStream stream;
  struct AdbcDriver* private_driver;
};

void ErrorArrayStreamRelease(struct ArrowArrayStream* stream) {
  if (stream->release != ErrorArrayStreamRelease || !stream->private_data) return;

  auto* private_data = reinterpret_cast<struct ErrorArrayStream*>(stream->private_data);
  private_data->stream.release(&private_data->stream);
  delete private_data;
  std::memset(stream, 0, sizeof(*stream));
}

const char* ErrorArrayStreamGetLastError(struct ArrowArrayStream* stream) {
  if (stream->release != ErrorArrayStreamRelease || !stream->private_data) return nullptr;
  auto* private_data = reinterpret_cast<struct ErrorArrayStream*>(stream->private_data);
  return private_data->stream.get_last_error(&private_data->stream);
}

int ErrorArrayStreamGetNext(struct ArrowArrayStream* stream, struct ArrowArray* array) {
  if (stream->release != ErrorArrayStreamRelease || !stream->private_data) return EINVAL;
  auto* private_data = reinterpret_cast<struct ErrorArrayStream*>(stream->private_data);
  return private_data->stream.get_next(&private_data->stream, array);
}

int ErrorArrayStreamGetSchema(struct ArrowArrayStream* stream,
                              struct ArrowSchema* schema) {
  if (stream->release != ErrorArrayStreamRelease || !stream->private_data) return EINVAL;
  auto* private_data = reinterpret_cast<struct ErrorArrayStream*>(stream->private_data);
  return private_data->stream.get_schema(&private_data->stream, schema);
}

// Default stubs

static const char kDefaultEntrypoint[] = "AdbcDriverInit";
}  // namespace

// Other helpers (intentionally not in an anonymous namespace so they can be tested)
ADBC_EXPORT std::filesystem::path InternalAdbcUserConfigDir() {
  std::filesystem::path config_dir;
#if defined(_WIN32)
  // SHGetFolderPath is just an alias to SHGetKnownFolderPath since Vista
  // so let's just call the updated function.
  PWSTR path = nullptr;
  auto hres = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path);
  if (!SUCCEEDED(hres)) {
    return config_dir;
  }

  std::wstring wpath(path);
  std::filesystem::path dir(std::move(wpath));
  if (!dir.empty()) {
    config_dir = std::filesystem::path(dir);
    config_dir /= "ADBC/Drivers";
  }
#elif defined(__APPLE__)
  auto dir = std::getenv("HOME");
  if (dir) {
    config_dir = std::filesystem::path(dir);
    config_dir /= "Library/Application Support/ADBC/Drivers";
  }
#elif defined(__linux__)
  auto dir = std::getenv("XDG_CONFIG_HOME");
  if (!dir) {
    dir = std::getenv("HOME");
    if (dir) {
      config_dir = std::filesystem::path(dir) /= ".config";
    }
  } else {
    config_dir = std::filesystem::path(dir);
  }

  if (!config_dir.empty()) {
    config_dir = config_dir / "adbc" / "drivers";
  }
#endif  // defined(_WIN32)

  return config_dir;
}

#if !defined(_WIN32)
std::filesystem::path InternalAdbcSystemConfigDir() {
#if defined(__APPLE__)
  return std::filesystem::path("/Library/Application Support/ADBC/Drivers");
#else
  return std::filesystem::path("/etc/adbc/drivers");
#endif  // defined(__APPLE__)
}
#endif  // !defined(_WIN32)

std::vector<std::filesystem::path> InternalAdbcParsePath(const std::string_view path) {
  std::vector<std::filesystem::path> result;
  if (path.empty()) {
    return result;
  }

#ifdef _WIN32
  constexpr char delimiter = ';';

  // pulling the logic from Go's filepath.SplitList function
  // where windows checks for quoted/escaped sections while splitting
  // but unix doesn't.
  // see
  // https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/path/filepath/path_windows.go
  bool in_quotes = false;
  size_t start = 0;
  for (size_t i = 0; i < path.size(); ++i) {
    if (path[i] == '"') {
      in_quotes = !in_quotes;
    } else if (path[i] == delimiter && !in_quotes) {
      result.emplace_back(path.substr(start, i - start));
      start = i + 1;
    }
  }
  result.emplace_back(path.substr(start));
#else
  constexpr char delimiter = ':';

  size_t start = 0;
  size_t end = 0;
  while ((end = path.find(delimiter, start)) != std::string::npos) {
    result.emplace_back(path.substr(start, end - start));
    start = end + 1;
  }
  result.emplace_back(path.substr(start));
#endif  // _WIN32

  // remove empty paths
  result.erase(std::remove_if(result.begin(), result.end(),
                              [](const auto& p) { return p.empty(); }),
               result.end());
  return result;
}

ADBC_EXPORT
ADBC_EXPORT
std::optional<ParseDriverUriResult> InternalAdbcParseDriverUri(std::string_view str) {
  std::string::size_type pos = str.find(":");
  if (pos == std::string::npos) {
    return std::nullopt;
  }

  std::string_view d = str.substr(0, pos);
  if (str.size() <= pos + 1) {
    return ParseDriverUriResult{d, std::nullopt, std::nullopt};
  }

#ifdef _WIN32
  if (std::filesystem::exists(std::filesystem::path(str))) {
    // No scheme, just a path
    return ParseDriverUriResult{str, std::nullopt, std::nullopt};
  }
#endif

  if (str[pos + 1] == '/') {  // scheme is also driver
    if (d == "profile" && str.size() > pos + 2) {
      // found a profile URI "profile://"
      return ParseDriverUriResult{"", std::nullopt, str.substr(pos + 3)};
    }
    return ParseDriverUriResult{d, str, std::nullopt};
  }

  // driver:scheme:.....
  return ParseDriverUriResult{d, str.substr(pos + 1), std::nullopt};
}

// Direct implementations of API methods

int AdbcErrorGetDetailCount(const struct AdbcError* error) {
  if (error->vendor_code == ADBC_ERROR_VENDOR_CODE_PRIVATE_DATA && error->private_data &&
      error->private_driver && error->private_driver->ErrorGetDetailCount) {
    return error->private_driver->ErrorGetDetailCount(error);
  }
  return 0;
}

struct AdbcErrorDetail AdbcErrorGetDetail(const struct AdbcError* error, int index) {
  if (error->vendor_code == ADBC_ERROR_VENDOR_CODE_PRIVATE_DATA && error->private_data &&
      error->private_driver && error->private_driver->ErrorGetDetail) {
    return error->private_driver->ErrorGetDetail(error, index);
  }
  return {nullptr, nullptr, 0};
}

const struct AdbcError* AdbcErrorFromArrayStream(struct ArrowArrayStream* stream,
                                                 AdbcStatusCode* status) {
  if (!stream->private_data || stream->release != ErrorArrayStreamRelease) {
    return nullptr;
  }
  auto* private_data = reinterpret_cast<struct ErrorArrayStream*>(stream->private_data);
  auto* error =
      private_data->private_driver->ErrorFromArrayStream(&private_data->stream, status);
  if (error) {
    const_cast<struct AdbcError*>(error)->private_driver = private_data->private_driver;
  }
  return error;
}

#define INIT_ERROR(ERROR, SOURCE)                                    \
  if ((ERROR) != nullptr &&                                          \
      (ERROR)->vendor_code == ADBC_ERROR_VENDOR_CODE_PRIVATE_DATA) { \
    (ERROR)->private_driver = (SOURCE)->private_driver;              \
  }

#define WRAP_STREAM(EXPR, OUT, SOURCE)                   \
  if (!(OUT)) {                                          \
    /* Happens for ExecuteQuery where out is optional */ \
    return EXPR;                                         \
  }                                                      \
  AdbcStatusCode status_code = EXPR;                     \
  ErrorArrayStreamInit(OUT, (SOURCE)->private_driver);   \
  return status_code;

struct ProfileGuard {
  AdbcConnectionProfile profile;
  explicit ProfileGuard() : profile{} {}
  ~ProfileGuard() {
    if (profile.release) {
      profile.release(&profile);
    }
  }
};

AdbcStatusCode InternalInitializeProfile(TempDatabase* args,
                                         const std::string_view profile,
                                         struct AdbcError* error) {
  if (!args->profile_provider) {
    args->profile_provider = AdbcProfileProviderFilesystem;
  }

  ProfileGuard guard{};
  CHECK_STATUS(args->profile_provider(
      profile.data(), args->additional_search_path_list.c_str(), &guard.profile, error));

  const char* driver_name = nullptr;
  AdbcDriverInitFunc init_func = nullptr;
  CHECK_STATUS(
      guard.profile.GetDriverName(&guard.profile, &driver_name, &init_func, error));
  if (driver_name != nullptr && strlen(driver_name) > 0) {
    args->driver = driver_name;
  }

  if (init_func != nullptr) {
    args->init_func = init_func;
  }

  const char** keys = nullptr;
  const char** values = nullptr;
  size_t num_options = 0;
  const int64_t* int_values = nullptr;
  const double* double_values = nullptr;

  CHECK_STATUS(
      guard.profile.GetOptions(&guard.profile, &keys, &values, &num_options, error));
  for (size_t i = 0; i < num_options; ++i) {
    // use try_emplace so we only add the option if there isn't
    // already an option with the same name
    std::string processed;
    CHECK_STATUS(ProcessProfileValue(values[i], processed, error));
    args->options.try_emplace(keys[i], processed);
  }

  CHECK_STATUS(guard.profile.GetIntOptions(&guard.profile, &keys, &int_values,
                                           &num_options, error));
  for (size_t i = 0; i < num_options; ++i) {
    // use try_emplace so we only add the option if there isn't
    // already an option with the same name
    args->int_options.try_emplace(keys[i], int_values[i]);
  }

  CHECK_STATUS(guard.profile.GetDoubleOptions(&guard.profile, &keys, &double_values,
                                              &num_options, error));
  for (size_t i = 0; i < num_options; ++i) {
    // use try_emplace so we only add the option if there isn't already an option with the
    // same name
    args->double_options.try_emplace(keys[i], double_values[i]);
  }

  return ADBC_STATUS_OK;
}

const char* AdbcStatusCodeMessage(AdbcStatusCode code) {
#define CASE(CONSTANT)         \
  case ADBC_STATUS_##CONSTANT: \
    return #CONSTANT;

  switch (code) {
    CASE(OK);
    CASE(UNKNOWN);
    CASE(NOT_IMPLEMENTED);
    CASE(NOT_FOUND);
    CASE(ALREADY_EXISTS);
    CASE(INVALID_ARGUMENT);
    CASE(INVALID_STATE);
    CASE(INVALID_DATA);
    CASE(INTEGRITY);
    CASE(INTERNAL);
    CASE(IO);
    CASE(CANCELLED);
    CASE(TIMEOUT);
    CASE(UNAUTHENTICATED);
    CASE(UNAUTHORIZED);
    default:
      return "(invalid code)";
  }
#undef CASE
}

AdbcStatusCode AdbcFindLoadDriver(const char* driver_name, const char* entrypoint,
                                  const int version, const AdbcLoadFlags load_options,
                                  const char* additional_search_path_list,
                                  void* raw_driver, struct AdbcError* error) {
  AdbcDriverInitFunc init_func = nullptr;
  std::string error_message;

  switch (version) {
    case ADBC_VERSION_1_0_0:
    case ADBC_VERSION_1_1_0:
      break;
    default:
      SetError(error, "Only ADBC 1.0.0 and 1.1.0 are supported");
      return ADBC_STATUS_NOT_IMPLEMENTED;
  }

  if (!raw_driver) {
    SetError(error, "Driver pointer is null");
    return ADBC_STATUS_INVALID_ARGUMENT;
  }
  if (!driver_name) {
    SetError(error, "Driver name is null");
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  ManagedLibrary library;
  DriverInfo info;
  if (entrypoint) {
    info.entrypoint = entrypoint;
  }

  std::vector<std::filesystem::path> additional_paths;
  if (additional_search_path_list) {
    additional_paths = InternalAdbcParsePath(additional_search_path_list);
  }

  auto* driver = reinterpret_cast<struct AdbcDriver*>(raw_driver);

  AdbcStatusCode status =
      library.GetDriverInfo(driver_name, load_options, additional_paths, info, error);
  if (status != ADBC_STATUS_OK) {
    driver->release = nullptr;
    return status;
  }

  void* load_handle = nullptr;
  if (!info.entrypoint.empty()) {
    status = library.Lookup(info.entrypoint.c_str(), &load_handle, error);
  } else {
    auto name = InternalAdbcDriverManagerDefaultEntrypoint(info.lib_path.string());
    assert(!name.empty());
    status = library.Lookup(name.c_str(), &load_handle, error);
    if (status != ADBC_STATUS_OK) {
      status = library.Lookup(kDefaultEntrypoint, &load_handle, error);
    }
  }

  if (status != ADBC_STATUS_OK) {
    library.Release();
    return status;
  }
  init_func = reinterpret_cast<AdbcDriverInitFunc>(load_handle);

  status = AdbcLoadDriverFromInitFunc(init_func, version, driver, error);
  if (status == ADBC_STATUS_OK) {
    ManagerDriverState* state = new ManagerDriverState;
    state->driver_release = driver->release;
    state->handle = std::move(library);
    driver->release = &ReleaseDriver;
    driver->private_manager = state;
  } else {
    library.Release();
  }
  return status;
}

