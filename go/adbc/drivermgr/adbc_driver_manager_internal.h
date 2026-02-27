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

#ifndef ADBC_DRIVER_MANAGER_INTERNAL_H
#define ADBC_DRIVER_MANAGER_INTERNAL_H

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "arrow-adbc/adbc.h"
#include "arrow-adbc/adbc_driver_manager.h"

// Forward declarations and shared utilities for driver manager implementation

// Forward declare C types from adbc_driver_manager.h for use in C++ contexts
struct AdbcConnectionProfile;
typedef AdbcStatusCode (*AdbcConnectionProfileProvider)(
    const char* profile_name, const char* additional_search_path_list,
    struct AdbcConnectionProfile* out, struct AdbcError* error);

namespace {

// Platform-specific type aliases
#ifdef _WIN32
using char_type = wchar_t;
using string_type = std::wstring;
#else
using char_type = char;
using string_type = std::string;
#endif

}  // namespace

// Enums
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

// Structs - forward declarations
struct ParseDriverUriResult {
  std::string_view driver;
  std::optional<std::string_view> uri;
  std::optional<std::string_view> profile;
};

struct DriverInfo {
  std::string manifest_file;
  int64_t manifest_version = 0;
  std::string driver_name;
  std::filesystem::path lib_path;
  std::string entrypoint;
  std::string version;
  std::string source;
};

struct OwnedError {
  struct AdbcError error = ADBC_ERROR_INIT;
  ~OwnedError();
};

inline OwnedError::~OwnedError() {
  if (error.release) {
    error.release(&error);
  }
}

// Error handling
void ReleaseError(struct AdbcError* error);
void SetError(struct AdbcError* error, const std::string& message);
void AppendError(struct AdbcError* error, const std::string& message);
void SetError(struct AdbcError* error, struct AdbcError* src_error);

// Platform helpers
#ifdef _WIN32
std::string Utf8Encode(const std::wstring& wstr);
std::wstring Utf8Decode(const std::string& str);
void GetWinError(std::string* buffer);
#endif

// Utilities
std::string CheckNonPrintableLibraryName(const std::string& name);
bool HasExtension(const std::filesystem::path& path, const std::string& ext);
void AddSearchPathsToError(const SearchPaths& search_paths, const SearchPathType& type,
                           std::string& error_message);

// Path management
std::vector<std::filesystem::path> InternalAdbcParsePath(const std::string_view path);
std::filesystem::path InternalAdbcUserConfigDir();
#if !defined(_WIN32)
std::filesystem::path InternalAdbcSystemConfigDir();
#endif
std::optional<ParseDriverUriResult> InternalAdbcParseDriverUri(std::string_view str);

// Search paths
SearchPaths GetSearchPaths(const AdbcLoadFlags levels);

// Driver loading
AdbcStatusCode LoadDriverManifest(const std::filesystem::path& driver_manifest,
                                  DriverInfo& info, struct AdbcError* error);
std::string InternalAdbcDriverManagerDefaultEntrypoint(const std::string& driver);

#ifdef _WIN32
class RegistryKey;
AdbcStatusCode LoadDriverFromRegistry(HKEY root, const std::wstring& driver_name,
                                      DriverInfo& info, struct AdbcError* error);
#endif

// Profile loading
struct FilesystemProfile;
AdbcStatusCode ProcessProfileValue(std::string_view value, std::string& out,
                                   struct AdbcError* error);
AdbcStatusCode LoadProfileFile(const std::filesystem::path& profile_path,
                               FilesystemProfile& profile, struct AdbcError* error);

// Initialization
/// Temporary state while the database is being configured.
struct TempDatabase {
  std::unordered_map<std::string, std::string> options;
  std::unordered_map<std::string, std::string> bytes_options;
  std::unordered_map<std::string, int64_t> int_options;
  std::unordered_map<std::string, double> double_options;
  std::string driver;
  std::string entrypoint;
  AdbcDriverInitFunc init_func = nullptr;
  AdbcLoadFlags load_flags = ADBC_LOAD_FLAG_ALLOW_RELATIVE_PATHS;
  std::string additional_search_path_list;
  AdbcConnectionProfileProvider profile_provider = nullptr;
};

/// Temporary state while the connection is being configured.
struct TempConnection {
  std::unordered_map<std::string, std::string> options;
  std::unordered_map<std::string, std::string> bytes_options;
  std::unordered_map<std::string, int64_t> int_options;
  std::unordered_map<std::string, double> double_options;
  AdbcConnectionProfile* connection_profile = nullptr;
};

AdbcStatusCode InternalInitializeProfile(TempDatabase* args,
                                         const std::string_view profile,
                                         struct AdbcError* error);

// Driver management
AdbcStatusCode AdbcFindLoadDriver(const char* driver_name, const char* entrypoint,
                                  const int version, const AdbcLoadFlags load_options,
                                  const char* additional_search_path_list,
                                  void* raw_driver, struct AdbcError* error);
// ReleaseDriver is implemented in adbc_driver_manager.cc but used by API implementations
AdbcStatusCode ReleaseDriver(struct AdbcDriver* driver, struct AdbcError* error);

#endif  // ADBC_DRIVER_MANAGER_INTERNAL_H
