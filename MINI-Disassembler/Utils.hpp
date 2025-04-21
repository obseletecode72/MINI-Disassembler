namespace Utils {
    namespace Process {
        void RefreshProcessList(bool force = false) {
            if (!App::State::needs_process_refresh && !force) return;

            App::State::cached_processes.clear();
            std::vector<DWORD> pids(1024);
            DWORD bytesReturned;
            while (true) {
                if (!EnumProcesses(pids.data(), pids.size() * sizeof(DWORD), &bytesReturned)) {
                    App::State::needs_process_refresh = false;
                    return;
                }
                if (bytesReturned < pids.size() * sizeof(DWORD)) {
                    pids.resize(bytesReturned / sizeof(DWORD));
                    break;
                }
                pids.resize(pids.size() * 2);
            }

            for (DWORD pid : pids) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                std::string name = "Unknown";
                if (hProcess) {
                    char processName[MAX_PATH];
                    if (GetModuleBaseNameA(hProcess, nullptr, processName, MAX_PATH)) {
                        name = processName;
                    }
                    CloseHandle(hProcess);
                }
                else if (pid == 0) {
                    name = "System Idle Process";
                }
                else if (pid == 4) {
                    name = "System";
                }
                App::State::cached_processes.push_back({ pid, name });
            }
            std::sort(App::State::cached_processes.begin(), App::State::cached_processes.end(), [](const auto& a, const auto& b) {
                std::string lower_a = a.second; std::transform(lower_a.begin(), lower_a.end(), lower_a.begin(), ::tolower);
                std::string lower_b = b.second; std::transform(lower_b.begin(), lower_b.end(), lower_b.begin(), ::tolower);
                return lower_a < lower_b;
                });
            App::State::needs_process_refresh = false;
        }

        std::string GetProcessNameFromCache(DWORD pid) {
            for (const auto& p : App::State::cached_processes) {
                if (p.first == pid) return p.second;
            }
            return "Unknown (Cache Miss)";
        }
    }

    namespace Module {
        void RefreshModuleList(HANDLE processHandle, bool force = false) {
            if (!processHandle) {
                App::State::cached_modules.clear();
                App::State::needs_module_refresh = true;
                App::State::previous_process_handle_for_modules = nullptr;
                return;
            }

            if (!App::State::needs_module_refresh && !force && App::State::previous_process_handle_for_modules == processHandle) return;

            App::State::cached_modules.clear();
            std::vector<HMODULE> modules(1024);
            DWORD bytesNeeded;
            while (true) {
                if (!EnumProcessModules(processHandle, modules.data(), modules.size() * sizeof(HMODULE), &bytesNeeded)) {
                    App::State::needs_module_refresh = false;
                    App::State::previous_process_handle_for_modules = processHandle;
                    return;
                }
                if (bytesNeeded <= modules.size() * sizeof(HMODULE)) {
                    modules.resize(bytesNeeded / sizeof(HMODULE));
                    break;
                }
                modules.resize(modules.size() * 2);
            }

            for (HMODULE hMod : modules) {
                char modulePath[MAX_PATH];
                std::string path = "Unknown";
                std::string name = "Unknown";
                uintptr_t base = 0;
                size_t size = 0;

                if (GetModuleFileNameExA(processHandle, hMod, modulePath, MAX_PATH)) {
                    path = modulePath;
                    size_t last_slash = path.find_last_of("/\\");
                    if (last_slash != std::string::npos) {
                        name = path.substr(last_slash + 1);
                    }
                    else {
                        name = path;
                    }
                }

                MODULEINFO mi;
                if (GetModuleInformation(processHandle, hMod, &mi, sizeof(mi))) {
                    base = (uintptr_t)mi.lpBaseOfDll;
                    size = mi.SizeOfImage;
                }

                App::State::cached_modules.emplace_back(hMod, name, base, size);
            }
            std::sort(App::State::cached_modules.begin(), App::State::cached_modules.end(), [](const auto& a, const auto& b) {
                std::string lower_a = std::get<1>(a); std::transform(lower_a.begin(), lower_a.end(), lower_a.begin(), ::tolower);
                std::string lower_b = std::get<1>(b); std::transform(lower_b.begin(), lower_b.end(), lower_b.begin(), ::tolower);
                return lower_a < lower_b;
                });

            App::State::needs_module_refresh = false;
            App::State::previous_process_handle_for_modules = processHandle;
        }
    }

    bool ContainsCaseInsensitive(const std::string& haystack, const std::string& needle) {
        if (needle.empty()) return true;
        if (haystack.empty()) return false;

        return std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](unsigned char ch1, unsigned char ch2) { return std::tolower(ch1) == std::tolower(ch2); }
        ) != haystack.end();
    }
}