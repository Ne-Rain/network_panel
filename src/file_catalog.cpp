#include "file_catalog.hpp"
#include "auth.hpp"
#include <cctype>
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

std::vector<FileRecord> load_files(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("file open failed");
    }
    std::vector<FileRecord> file_list;
    std::string line;
    std::size_t line_id = 0;
    while (std::getline(in, line)) {
        // 跳过空行，以及只包含空格、Tab、回车的行
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            continue;
        }
        ++line_id;
        FileRecord file_record;
        std::istringstream iss(line);
        if (!(iss >> file_record.file_id >> file_record.display_name >> file_record.owner_group >>
              file_record.storage_path)) {
            throw std::runtime_error("line_id: " + std::to_string(line_id) + "is illegal");
        }
        std::string tmp;
        if (iss >> tmp) { // 判断是否有多余字段
            throw std::runtime_error("line_id: " + std::to_string(line_id) + "is illegal");
        }
        file_list.push_back(file_record);
    }
    if (in.bad()) { // 读取文件发生IO错误
        throw std::runtime_error("Failed to read account file: " + path);
    }
    if (file_list.empty()) {
        throw std::runtime_error("account file is empty");
    }
    return file_list;
}

std::vector<FileRecord> get_group_file_list(const std::vector<FileRecord>& file_list, std::string group) {
    std::vector<FileRecord> group_file_list;
    for (const auto file_record : file_list) {
        if (file_record.owner_group == group || file_record.owner_group == "PUBLIC") {
            group_file_list.push_back(file_record);
        }
    }
    return group_file_list;
}