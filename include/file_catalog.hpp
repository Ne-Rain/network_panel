#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

enum class FileType { File, Image, Video, Audio, Archive, Other };

struct FileRecord {
    std::size_t file_id;
    std::string display_name;
    std::uint64_t size_bytes;
    FileType type;
    std::string uploadedAt;
    std::string owner_group;
    std::string storage_path;
};

void parse_file_type(const std::string& token, FileType& result);

std::string file_type_to_string(FileType type);

std::unordered_map<std::size_t, FileRecord> load_files(const std::string& path);

std::vector<FileRecord> get_group_file_list(
    const std::unordered_map<std::size_t, FileRecord>& file_list,
    std::string group);

FileType get_file_type(const std::string& file_name);
