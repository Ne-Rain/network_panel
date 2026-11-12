#pragma once

#include <cstddef>
#include <string>

enum class TaskState { Restart, Running, Confirming, Success, Failed };

struct TaskRecord {
    std::string task_id;
    std::string owner_session_id;
    std::size_t sent_bytes;
    std::size_t total_bytes;
    TaskState state = TaskState::Restart;
};

std::string state_to_string(TaskState state);