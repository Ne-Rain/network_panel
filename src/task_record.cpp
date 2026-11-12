#include "task_record.hpp"

std::string state_to_string(TaskState state) {
    switch (state) {
    case TaskState::Restart:
        return "restart";
    case TaskState::Running:
        return "running";
    case TaskState::Confirming:
        return "confirming";
    case TaskState::Success:
        return "success";
    case TaskState::Failed:
        return "failed";
    }
}