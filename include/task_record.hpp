#pragma once

#include <cstddef>
#include <string>

enum class TaskState { Restart, Running, Confirming, Success, Failed };

struct UploadTask {
    std::string task_id;
    std::string owner_session_id;
    std::size_t sent_bytes;
    std::size_t total_bytes;
    TaskState state = TaskState::Restart;
};

struct DownloadTask {
    std::string task_id;
    std::string owner_session_id;
    std::size_t received_bytes;
    std::size_t total_bytes;
    bool total_known = false;
    TaskState state = TaskState::Restart;
};

std::string state_to_string(TaskState state);