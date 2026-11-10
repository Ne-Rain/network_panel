#pragma once
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string>

bool decode_base64(const std::string& encoded, std::string& decoded);

bool string_to_size_t(const std::string& s, std::size_t& value);

std::string make_local_time();