#pragma once

#include "auth.hpp"
#include <cstddef>
#include <string>
#include <vector>

struct FileRecord {
    std::size_t file_id;
    std::string display_name;
    std::string owner_group;
    std::string storage_path;
};

std::vector<FileRecord> load_files(const std::string& path);

std::vector<FileRecord> get_group_file_list(const std::string& authorization,
                                            const std::vector<FileRecord>& file_list,
                                            const std::unordered_map<std::string, GroupAccount>& accounts,
                                            std::string& group);