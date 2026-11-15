#pragma once
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string>

bool decode_base64(const std::string& encoded, std::string& decoded);

bool string_to_size_t(const std::string& s, std::size_t& value);

void append_json_string(std::string& out, const std::string& value);

std::string make_local_time();

std::string make_rand_id();

std::string encode_query_value(const std::string& value);

std::string make_tmp_path(const std::string& tmp_dir);