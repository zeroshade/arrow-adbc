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
#endif  // defined(_WIN32)

#include <toml++/toml.hpp>
#include "arrow-adbc/adbc.h"
#include "arrow-adbc/adbc_driver_manager.h"
#include "adbc_driver_manager_internal.h"

#include <filesystem>
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

namespace {

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

#if 0  // Unused - kept for potential future use
#ifdef _WIN32
static const wchar_t* kAdbcProfilePath = L"ADBC_PROFILE_PATH";
#else
static const char* kAdbcProfilePath = "ADBC_PROFILE_PATH";
#endif  // _WIN32
#endif

}  // namespace (reopen after moving types outside)

// Re-enter anonymous namespace for helper functions
namespace {

static AdbcStatusCode ProcessProfileValueInternal(std::string_view value, std::string& out,
                                                  struct AdbcError* error) {
  if (value.empty()) {
    SetError(error, "Profile value is null");
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  static const std::regex pattern(R"(\{\{\s*([^{}]*?)\s*\}\})");
  auto end_of_last_match = value.begin();
  auto begin = std::regex_iterator(value.begin(), value.end(), pattern);
  auto end = decltype(begin){};
  std::match_results<std::string_view::iterator>::difference_type pos_last_match = 0;

  out.resize(0);
  for (auto itr = begin; itr != end; ++itr) {
    auto match = *itr;
    auto pos_match = match.position();
    auto diff = pos_match - pos_last_match;
    auto start_match = end_of_last_match;
    std::advance(start_match, diff);
    out.append(end_of_last_match, start_match);

    const auto content = match[1].str();
    if (content.rfind("env_var(", 0) != 0) {
      SetError(error, "Unsupported interpolation type in profile value: " + content);
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

    if (content[content.size() - 1] != ')') {
      SetError(error, "Malformed env_var() profile value: missing closing parenthesis");
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

    const auto env_var_name = content.substr(8, content.size() - 9);
    if (env_var_name.empty()) {
      SetError(error,
               "Malformed env_var() profile value: missing environment variable name");
      return ADBC_STATUS_INVALID_ARGUMENT;
    }

#ifdef _WIN32
    auto local_env_var = Utf8Decode(std::string(env_var_name));
    DWORD required_size = GetEnvironmentVariableW(local_env_var.c_str(), NULL, 0);
    if (required_size == 0) {
      out = "";
      return ADBC_STATUS_OK;
    }

    std::wstring wvalue;
    wvalue.resize(required_size);
    DWORD actual_size =
        GetEnvironmentVariableW(local_env_var.c_str(), wvalue.data(), required_size);
    // remove null terminator
    wvalue.resize(actual_size);
    const auto env_var_value = Utf8Encode(wvalue);
#else
    const char* env_value = std::getenv(env_var_name.c_str());
    if (!env_value) {
      out = "";
      return ADBC_STATUS_OK;
    }
    const auto env_var_value = std::string(env_value);
#endif
    out.append(env_var_value);

    auto length_match = match.length();
    pos_last_match = pos_match + length_match;
    end_of_last_match = start_match;
    std::advance(end_of_last_match, length_match);
  }

  out.append(end_of_last_match, value.end());
  return ADBC_STATUS_OK;
}

#if 0  // Unused - kept for potential future use
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
#endif

}  // namespace (closing early to move types outside)

// FilesystemProfile needs external linkage for use in internal header
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

// Public implementations (non-static for use across translation units)
AdbcStatusCode ProcessProfileValue(std::string_view value, std::string& out,
                                   struct AdbcError* error) {
  return ProcessProfileValueInternal(value, out, error);
}

AdbcStatusCode LoadProfileFile(const std::filesystem::path& profile_path,
                               FilesystemProfile& profile, struct AdbcError* error) {
  toml::table config;
  try {
    config = toml::parse_file(profile_path.native());
  } catch (const toml::parse_error& err) {
    std::string message = "Could not open profile. ";
    message += err.what();
    message += ". Profile: ";
    message += profile_path.string();
    SetError(error, std::move(message));
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  profile.path = profile_path;
  if (!config["version"].is_integer()) {
    std::string message =
        "Profile version is not an integer in profile '" + profile_path.string() + "'";
    SetError(error, std::move(message));
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  const auto version = config["version"].value_or(int64_t(1));
  switch (version) {
    case 1:
      break;
    default: {
      std::string message =
          "Profile version '" + std::to_string(version) +
          "' is not supported by this driver manager. Profile: " + profile_path.string();
      SetError(error, std::move(message));
      return ADBC_STATUS_INVALID_ARGUMENT;
    }
  }

  profile.driver = config["driver"].value_or(""s);

  auto options = config.at_path("options");
  if (!options.is_table()) {
    std::string message =
        "Profile options is not a table in profile '" + profile_path.string() + "'";
    SetError(error, std::move(message));
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  auto* options_table = options.as_table();
  ProfileVisitor v{profile, profile_path, error};
  if (!v.VisitTable("", *options_table)) {
    return ADBC_STATUS_INVALID_ARGUMENT;
  }

  return ADBC_STATUS_OK;
}

// Reopen anonymous namespace for unused helper (commented out to avoid unused warning)
namespace {

// Unused - kept for potential future use
#if 0
static SearchPaths GetProfileSearchPaths(const char* additional_search_path_list) {
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
#endif

}  // namespace
