#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

struct FileRecord {
    std::size_t file_id;
    std::string display_name;
    std::string owner_group;
    std::string storage_path;
};

std::unordered_map<std::size_t, FileRecord> load_files(const std::string& path);

std::vector<FileRecord> get_group_file_list(const std::unordered_map<std::size_t, FileRecord>& file_list,
                                            std::string group);