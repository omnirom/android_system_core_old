/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <chrono>
#include <functional>
#include <iostream>
#include <ratio>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static constexpr char VERSION[] = "0";

// Self-contained class for collecting and reporting benchmark metrics
// (currently only execution time).
class Collector {
    using time_point = std::chrono::time_point<std::chrono::steady_clock>;
    using time_unit = std::chrono::duration<double, std::milli>;

    struct Metric {
        std::string workload;
        time_unit exec_time;
        Metric(const std::string& workload, const time_unit& exec_time)
            : workload(workload), exec_time(exec_time) {}
    };

    static constexpr char TIME_UNIT[] = "ms";
    static constexpr char VERSION[] = "0";
    std::vector<Metric> metrics;
    time_point reset_time;

  public:
    Collector() { reset(); }

    void reset() { reset_time = std::chrono::steady_clock::now(); }

    void collect_metric(const std::string& workload) {
        auto elapsed = std::chrono::steady_clock::now() - reset_time;
        metrics.emplace_back(workload, std::chrono::duration_cast<time_unit>(elapsed));
    }

    void report_metrics() {
        for (const Metric& metric : metrics)
            std::cout << VERSION << ";" << metric.workload << ";" << metric.exec_time.count() << ";"
                      << TIME_UNIT << std::endl;
    }
};

struct Command {
    static constexpr char CREATE[] = "create";
    static constexpr char DELETE[] = "delete";
    static constexpr char MOVE[] = "move";
    static constexpr char HARDLINK[] = "hardlink";
    static constexpr char SYMLINK[] = "symlink";
    static constexpr char READDIR[] = "readdir";
    std::string workload;
    std::string from_dir;
    std::string from_basename;
    std::string to_dir;
    std::string to_basename;
    bool drop_state;
    int n_file;

    Command() { reset(); }

    std::string to_string() const {
        std::stringstream string_repr;
        string_repr << "Command {\n";
        string_repr << "\t.workload = " << workload << ",\n";
        string_repr << "\t.from_dir = " << from_dir << ",\n";
        string_repr << "\t.from_basename = " << from_basename << ",\n";
        string_repr << "\t.to_dir = " << to_dir << ",\n";
        string_repr << "\t.to_basename = " << to_basename << ",\n";
        string_repr << "\t.drop_state = " << drop_state << ",\n";
        string_repr << "\t.n_file = " << n_file << "\n";
        string_repr << "}\n";
        return string_repr.str();
    }

    void reset() {
        workload = "";
        from_dir = to_dir = "./";
        from_basename = "from_file";
        to_basename = "to_file";
        drop_state = true;
        n_file = 0;
    }
};

void print_version() {
    std::cout << VERSION << std::endl;
}

void print_commands(const std::vector<Command>& commands) {
    for (const Command& command : commands) std::cout << command.to_string();
}

void usage(std::ostream& ostr, const std::string& program_name) {
    Command command;

    ostr << "Usage: " << program_name << " [global_options] {[workload_options] -w WORKLOAD_T}\n";
    ostr << "WORKLOAD_T = {" << Command::CREATE << ", " << Command::DELETE << ", " << Command::MOVE
         << ", " << Command::HARDLINK << ", " << Command::SYMLINK << "}\n";
    ostr << "Global options\n";
    ostr << "\t-v: Print version.\n";
    ostr << "\t-p: Print parsed workloads and exit.\n";
    ostr << "Workload options\n";
    ostr << "\t-d DIR\t\t: Work directory for " << Command::CREATE << "/" << Command::DELETE
         << " (default '" << command.from_dir << "').\n";
    ostr << "\t-f FROM-DIR\t: Source directory for " << Command::MOVE << "/" << Command::SYMLINK
         << "/" << Command::HARDLINK << " (default '" << command.from_dir << "').\n";
    ostr << "\t-t TO-DIR\t: Destination directory for " << Command::MOVE << "/" << Command::SYMLINK
         << "/" << Command::HARDLINK << " (default '" << command.to_dir << "').\n";
    ostr << "\t-n N_FILES\t: Number of files to create/delete etc. (default " << command.n_file
         << ").\n";
    ostr << "\t-s\t\t: Do not drop state (caches) before running the workload (default "
         << !command.drop_state << ").\n";
    ostr << "NOTE: -w WORKLOAD_T defines a new command and must come after its workload_options."
         << std::endl;
}

void drop_state() {
    // Drop inode/dentry/page caches.
    std::system("sync; echo 3 > /proc/sys/vm/drop_caches");
}

static constexpr int OPEN_DIR_FLAGS = O_RDONLY | O_DIRECTORY | O_PATH | O_CLOEXEC;

bool delete_files(const std::string& dir, int n_file, const std::string& basename) {
    int dir_fd = open(dir.c_str(), OPEN_DIR_FLAGS);
    if (dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open work directory '" << dir << "', error '" << strerror(error)
                  << "'." << std::endl;
        return false;
    }

    bool ret = true;
    for (int i = 0; i < n_file; i++) {
        std::string filename = basename + std::to_string(i);
        ret = ret && (unlinkat(dir_fd, filename.c_str(), 0) == 0);
    }

    if (!ret) std::cerr << "Failed to delete at least one of the files" << std::endl;
    close(dir_fd);
    return ret;
}

bool create_files(const std::string& dir, int n_file, const std::string& basename) {
    int dir_fd = open(dir.c_str(), OPEN_DIR_FLAGS);
    if (dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open work directory '" << dir << "', error '" << strerror(error)
                  << "'." << std::endl;
        return false;
    }

    bool ret = true;
    for (int i = 0; i < n_file; i++) {
        std::string filename = basename + std::to_string(i);
        int fd = openat(dir_fd, filename.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0777);
        ret = ret && fd != -1;
        close(fd);
    }

    close(dir_fd);
    if (!ret) {
        std::cerr << "Failed to open at least one of the files" << std::endl;
        delete_files(dir, n_file, basename);
    }
    return ret;
}

bool move_files(const std::string& from_dir, const std::string& to_dir, int n_file,
                const std::string& from_basename, const std::string& to_basename) {
    int from_dir_fd = open(from_dir.c_str(), OPEN_DIR_FLAGS);
    if (from_dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open source directory '" << from_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        return false;
    }
    int to_dir_fd = open(to_dir.c_str(), OPEN_DIR_FLAGS);
    if (to_dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open destination directory '" << to_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        close(from_dir_fd);
        return false;
    }

    bool ret = true;
    for (int i = 0; i < n_file; i++) {
        std::string from_filename = from_basename + std::to_string(i);
        std::string to_filename = to_basename + std::to_string(i);
        ret = ret &&
              (renameat(from_dir_fd, from_filename.c_str(), to_dir_fd, to_filename.c_str()) == 0);
    }

    if (!ret) std::cerr << "Failed to move at least one of the files" << std::endl;
    close(from_dir_fd);
    close(from_dir_fd);
    return ret;
}

bool hardlink_files(const std::string& from_dir, const std::string& to_dir, int n_file,
                    const std::string& from_basename, const std::string& to_basename) {
    int from_dir_fd = open(from_dir.c_str(), OPEN_DIR_FLAGS);
    if (from_dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open source directory '" << from_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        return false;
    }
    int to_dir_fd = open(to_dir.c_str(), OPEN_DIR_FLAGS);
    if (to_dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open destination directory '" << to_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        close(from_dir_fd);
        return false;
    }

    bool ret = true;
    for (int i = 0; i < n_file; i++) {
        std::string from_filename = from_basename + std::to_string(i);
        std::string to_filename = to_basename + std::to_string(i);
        ret = ret &&
              (linkat(from_dir_fd, from_filename.c_str(), to_dir_fd, to_filename.c_str(), 0) == 0);
    }

    if (!ret) std::cerr << "Failed to hardlink at least one of the files" << std::endl;
    close(from_dir_fd);
    close(to_dir_fd);
    return ret;
}

bool symlink_files(std::string from_dir, const std::string& to_dir, int n_file,
                   const std::string& from_basename, const std::string& to_basename) {
    if (from_dir.back() != '/') from_dir.push_back('/');
    int to_dir_fd = open(to_dir.c_str(), OPEN_DIR_FLAGS);
    if (to_dir_fd == -1) {
        int error = errno;
        std::cerr << "Failed to open destination directory '" << to_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        return false;
    }

    bool ret = true;
    for (int i = 0; i < n_file; i++) {
        std::string from_filepath = from_dir + from_basename + std::to_string(i);
        std::string to_filename = to_basename + std::to_string(i);
        ret = ret && (symlinkat(from_filepath.c_str(), to_dir_fd, to_filename.c_str()) == 0);
    }

    if (!ret) std::cerr << "Failed to symlink at least one of the files" << std::endl;
    close(to_dir_fd);
    return ret;
}

bool exhaustive_readdir(const std::string& from_dir) {
    DIR* dir = opendir(from_dir.c_str());
    if (dir == nullptr) {
        int error = errno;
        std::cerr << "Failed to open working directory '" << from_dir << "', error '"
                  << strerror(error) << "'." << std::endl;
        return false;
    }

    errno = 0;
    while (readdir(dir) != nullptr)
        ;
    // In case of failure readdir returns nullptr and sets errno accordingly (to
    // something != 0).
    // In case of success readdir != nullptr and errno is not changed.
    // Source: man 3 readdir.
    bool ret = errno == 0;
    closedir(dir);
    return ret;
}

void create_workload(Collector* collector, const Command& command) {
    if (command.drop_state) drop_state();
    collector->reset();
    if (create_files(command.from_dir, command.n_file, command.from_basename))
        collector->collect_metric(command.workload);

    delete_files(command.from_dir, command.n_file, command.from_basename);
}

void delete_workload(Collector* collector, const Command& command) {
    if (!create_files(command.from_dir, command.n_file, command.from_basename)) return;

    if (command.drop_state) drop_state();
    collector->reset();
    if (delete_files(command.from_dir, command.n_file, command.from_basename))
        collector->collect_metric(command.workload);
}

void move_workload(Collector* collector, const Command& command) {
    if (!create_files(command.from_dir, command.n_file, command.from_basename)) return;

    if (command.drop_state) drop_state();
    collector->reset();
    if (move_files(command.from_dir, command.to_dir, command.n_file, command.from_basename,
                   command.to_basename))
        collector->collect_metric(command.workload);

    delete_files(command.to_dir, command.n_file, command.to_basename);
}

void hardlink_workload(Collector* collector, const Command& command) {
    if (!create_files(command.from_dir, command.n_file, command.from_basename)) return;

    if (command.drop_state) drop_state();
    collector->reset();
    if (hardlink_files(command.from_dir, command.to_dir, command.n_file, command.from_basename,
                       command.to_basename))
        collector->collect_metric(command.workload);

    delete_files(command.from_dir, command.n_file, command.from_basename);
    delete_files(command.to_dir, command.n_file, command.to_basename);
}

void symlink_workload(Collector* collector, const Command& command) {
    if (!create_files(command.from_dir, command.n_file, command.from_basename)) return;

    if (command.drop_state) drop_state();
    collector->reset();
    if (symlink_files(command.from_dir, command.to_dir, command.n_file, command.from_basename,
                      command.to_basename))
        collector->collect_metric(command.workload);

    delete_files(command.to_dir, command.n_file, command.to_basename);
    delete_files(command.from_dir, command.n_file, command.from_basename);
}

void readdir_workload(Collector* collector, const Command& command) {
    if (!create_files(command.from_dir, command.n_file, command.from_basename)) return;

    if (command.drop_state) drop_state();
    collector->reset();
    if (exhaustive_readdir(command.from_dir)) collector->collect_metric(command.workload);

    delete_files(command.from_dir, command.n_file, command.from_basename);
}

using workload_executor_t = std::function<void(Collector*, const Command&)>;

std::unordered_map<std::string, workload_executor_t> executors = {
        {Command::CREATE, create_workload},   {Command::DELETE, delete_workload},
        {Command::MOVE, move_workload},       {Command::HARDLINK, hardlink_workload},
        {Command::SYMLINK, symlink_workload}, {Command::READDIR, readdir_workload}};

int main(int argc, char** argv) {
    std::vector<Command> commands;
    Command command;
    int opt;

    while ((opt = getopt(argc, argv, "hvpsw:d:f:t:n:")) != -1) {
        switch (opt) {
            case 'h':
                usage(std::cout, argv[0]);
                return EXIT_SUCCESS;
            case 'v':
                print_version();
                return EXIT_SUCCESS;
            case 'p':
                print_commands(commands);
                return EXIT_SUCCESS;
            case 's':
                command.drop_state = false;
                break;
            case 'w':
                command.workload = optarg;
                commands.push_back(command);
                command.reset();
                break;
            case 'd':
            case 'f':
                command.from_dir = optarg;
                break;
            case 't':
                command.to_dir = optarg;
                break;
            case 'n':
                command.n_file = std::stoi(optarg);
                break;
            default:
                usage(std::cerr, argv[0]);
                return EXIT_FAILURE;
        }
    }

    Collector collector;
    for (const Command& command : commands) {
        auto executor = executors.find(command.workload);
        if (executor == executors.end()) continue;
        executor->second(&collector, command);
    }
    collector.report_metrics();

    return EXIT_SUCCESS;
}
