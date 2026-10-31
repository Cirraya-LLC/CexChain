// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <string>
#include <unistd.h>

#include <cexchain/console/activity.hpp>

namespace cexchain::console {

namespace {

std::mutex& log_mutex() {
    static std::mutex m;
    return m;
}

std::filesystem::path log_path(const std::filesystem::path& directory) {
    return directory / "activity.jsonl";
}

} // namespace

nlohmann::json activity_json(const Activity& a) {
    return {{"at", a.at}, {"user", a.user}, {"action", a.action}, {"detail", a.detail}};
}

void record_activity(const std::filesystem::path& directory, const Activity& activity) noexcept {
    try {
        const std::lock_guard lock(log_mutex());
        std::filesystem::create_directories(directory);
        const std::filesystem::path path = log_path(directory);
        std::error_code ec;
        if (std::filesystem::file_size(path, ec) > max_activity_log && !ec) {
            std::filesystem::rename(path, directory / "activity.1.jsonl", ec);
        }
        const std::string line = activity_json(activity).dump() + "\n";
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) {
            return;
        }
        std::size_t done = 0;
        while (done < line.size()) {
            const auto wrote = ::write(fd, line.data() + done, line.size() - done);
            if (wrote <= 0) {
                break;
            }
            done += static_cast<std::size_t>(wrote);
        }
        ::close(fd);
    } catch (...) {
        // The log is a record of the console's administration, not a
        // condition of it.
    }
}

std::vector<Activity> read_activity(const std::filesystem::path& directory, std::size_t limit) {
    std::vector<Activity> out;
    const std::lock_guard lock(log_mutex());
    for (const auto& name : {"activity.jsonl", "activity.1.jsonl"}) {
        std::ifstream file(directory / name);
        std::vector<Activity> read;
        for (std::string line; std::getline(file, line);) {
            const auto value = nlohmann::json::parse(line, nullptr, false);
            if (!value.is_object() || !value.contains("at") || !value["at"].is_number_unsigned()) {
                continue;
            }
            read.push_back({value["at"].get<protocol::Timestamp>(), value.value("user", ""),
                            value.value("action", ""),
                            value.value("detail", nlohmann::json::object())});
        }
        std::ranges::reverse(read);
        for (Activity& a : read) {
            if (out.size() >= limit) {
                return out;
            }
            out.push_back(std::move(a));
        }
    }
    return out;
}

} // namespace cexchain::console
