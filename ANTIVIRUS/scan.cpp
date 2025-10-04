#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <openssl/sha.h>
#include <yara.h>
#include <filesystem>
#include <iomanip>    // <-- add this for setfill/setw
#include <chrono>     // <-- add this for chrono

// 全局变量
YR_RULES* yara_rules = nullptr;

// 初始化函数
extern "C" __declspec(dllexport) bool init_yara_rules(const char* rule_text) {
    if (yara_rules != nullptr) {
        yr_rules_destroy(yara_rules);
        yara_rules = nullptr;
    }

    YR_COMPILER* compiler = nullptr;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        return false;
    }

    result = yr_compiler_add_string(compiler, rule_text, nullptr);
    if (result != 0) {
        yr_compiler_destroy(compiler);
        return false;
    }

    result = yr_compiler_get_rules(compiler, &yara_rules);
    yr_compiler_destroy(compiler);

    return result == ERROR_SUCCESS;
}

// 扫描文件的回调函数
static int scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matches = (std::vector<std::string>*)user_data;
        matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// 文件扫描函数
extern "C" __declspec(dllexport) char* scan_file(const char* file_path) {
    if (yara_rules == nullptr) {
        return nullptr;
    }

    std::vector<std::string> matches;
    int result = yr_rules_scan_file(yara_rules, file_path, SCAN_FLAGS_FAST_MODE, scan_callback, &matches, 0);
    if (result != ERROR_SUCCESS) {
        return nullptr;
    }

    if (matches.empty()) {
        return nullptr;
    }

    // 将匹配的规则名称组合成逗号分隔的字符串
    std::ostringstream oss;
    for (size_t i = 0; i < matches.size(); ++i) {
        if (i != 0) {
            oss << ", ";
        }
        oss << matches[i];
    }

    // 返回动态分配的字符串（调用者需释放）
    std::string result_str = oss.str();
    char* cstr = new char[result_str.length() + 1];
    std::strcpy(cstr, result_str.c_str());
    return cstr;
}

// 计算SHA256哈希值
extern "C" __declspec(dllexport) char* calculate_sha256(const char* file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return nullptr;
    }

    const size_t buffer_size = 8192;
    char buffer[buffer_size];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    while (file.read(buffer, buffer_size) || file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    // 将哈希转换为十六进制字符串
    std::ostringstream oss;
    oss << std::hex << std::setfill('0'); // setfill from <iomanip>
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(hash[i]); // setw from <iomanip>
    }

    std::string hash_str = oss.str();
    char* result = new char[hash_str.length() + 1];
    std::strcpy(result, hash_str.c_str());
    return result;
}

// 内存扫描函数
extern "C" __declspec(dllexport) char* scan_process_memory(int pid) {
    if (yara_rules == nullptr) {
        return nullptr;
    }

    HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process_handle == nullptr) {
        return nullptr;
    }

    std::vector<std::string> matches;
    
    // 获取进程内存信息（简化实现）
    MEMORY_BASIC_INFORMATION mem_info;
    SIZE_T offset = 0;
    
    while (VirtualQueryEx(process_handle, (LPCVOID)offset, &mem_info, sizeof(mem_info))) {
        if (mem_info.State == MEM_COMMIT && 
            (mem_info.Protect & PAGE_EXECUTE_READWRITE || 
             mem_info.Protect & PAGE_EXECUTE_WRITECOPY)) {
            
            // 读取内存并扫描
            std::vector<char> buffer(mem_info.RegionSize);
            SIZE_T bytes_read;
            if (ReadProcessMemory(process_handle, mem_info.BaseAddress, buffer.data(), mem_info.RegionSize, &bytes_read)) {
                int result = yr_rules_scan_mem(
                    yara_rules,
                    reinterpret_cast<const uint8_t*>(buffer.data()), // <-- fix type for YARA
                    bytes_read,
                    SCAN_FLAGS_FAST_MODE,
                    scan_callback,
                    &matches,
                    0
                );
                // 忽略结果，继续扫描
            }
        }
        offset = (SIZE_T)mem_info.BaseAddress + mem_info.RegionSize;
    }

    CloseHandle(process_handle);

    if (matches.empty()) {
        return nullptr;
    }

    // 将匹配的规则名称组合成逗号分隔的字符串
    std::ostringstream oss;
    for (size_t i = 0; i < matches.size(); ++i) {
        if (i != 0) {
            oss << ", ";
        }
        oss << matches[i];
    }

    std::string result_str = oss.str();
    char* cstr = new char[result_str.length() + 1];
    std::strcpy(cstr, result_str.c_str());
    return cstr;
}

// 隔离文件函数
extern "C" __declspec(dllexport) bool quarantine_file(const char* file_path, const char* quarantine_dir) {
    try {
        std::filesystem::path src(file_path);
        if (!std::filesystem::exists(src)) {
            return false;
        }
        std::filesystem::path qdir(quarantine_dir);
        if (!std::filesystem::exists(qdir)) {
            std::filesystem::create_directories(qdir);
        }
        // 生成唯一文件名
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        char timestamp[32];
        std::strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tm);
        std::string base = src.stem().string();
        std::string ext = src.extension().string();
        std::string quarantine_name = base + "_" + timestamp + ext;
        std::filesystem::path dest = qdir / quarantine_name;
        std::filesystem::rename(src, dest);
        return true;
    } catch (...) {
        return false;
    }
}

// 删除文件函数
extern "C" __declspec(dllexport) bool delete_file(const char* file_path) {
    try {
        std::filesystem::path src(file_path);
        if (!std::filesystem::exists(src)) {
            return false;
        }
        std::filesystem::remove(src);
        return true;
    } catch (...) {
        return false;
    }
}

// 释放内存函数
extern "C" __declspec(dllexport) void free_memory(char* ptr) {
    if (ptr != nullptr) {
        delete[] ptr;
    }
}

// 清理函数
extern "C" __declspec(dllexport) void cleanup() {
    if (yara_rules != nullptr) {
        yr_rules_destroy(yara_rules);
        yara_rules = nullptr;
    }
    yr_finalize();
}

// 初始化函数
extern "C" __declspec(dllexport) bool initialize() {
    return yr_initialize() == ERROR_SUCCESS;
}

// 阻止病毒執行程式功能：根據進程名稱終止進程
extern "C" __declspec(dllexport) int block_process_by_name(const char* process_name) {
    int killed_count = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
#ifdef UNICODE
            std::wstring ws(pe.szExeFile);
            std::string exe_name(ws.begin(), ws.end());
#else
            std::string exe_name(pe.szExeFile);
#endif
            if (_stricmp(exe_name.c_str(), process_name) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (TerminateProcess(hProcess, 1)) {
                        ++killed_count;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return killed_count;
}
