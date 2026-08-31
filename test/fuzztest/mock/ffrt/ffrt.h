/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TEST_FUZZTEST_MOCK_FFRT_FFRT_H
#define TEST_FUZZTEST_MOCK_FFRT_FFRT_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

namespace ffrt {
    using mutex = std::mutex;
    using recursive_mutex = std::recursive_mutex;
    using condition_variable = std::condition_variable;

    enum qos {
        qos_inherit = -1,
        qos_default = 0,
        qos_user_initiated = 1,
        qos_utility = 2,
        qos_background = 3,
        qos_deadline_requested = 5,
    };

    class task_attr {
    public:
        task_attr& qos(ffrt::qos) { return *this; }
    };

    enum queue_type_t {
        queue_serial,
        queue_concurrent,
    };

    class queue {
    public:
        queue() = default;
        queue(ffrt::queue_type_t, const std::string&) {}
        template<typename Func>
        void submit(Func&& func) { func(); }
    };

    class thread {
    public:
        thread() = default;
        ~thread() = default;
        template<typename Func, typename... Args>
        explicit thread(Func&&, Args&&...) {}
        thread(const thread&) = delete;
        thread& operator=(const thread&) = delete;
        thread(thread&&) noexcept {}
        thread& operator=(thread&&) noexcept { return *this; }
        void join() {}
        void detach() {}
        bool joinable() const { return false; }
    };

    namespace this_task {
        template<typename Rep, typename Period>
        inline void sleep_for(const std::chrono::duration<Rep, Period>&) {}
    }

    template<typename Func>
    inline void submit(Func&& func) { func(); }
    template<typename Func>
    inline void submit(Func&& func, const std::vector<void*>&, const std::vector<void*>&,
        const task_attr&) { func(); }
    template<typename Func, typename... Args>
    inline void submit(Func&& func, Args&&... args) { func(); }
    inline void wait() {}
}

#endif  // TEST_FUZZTEST_MOCK_FFRT_FFRT_H
