#if defined(__ANDROID__) || defined(__APPLE__)
#include <dlfcn.h>
#endif
#ifdef __APPLE__
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <CoreFoundation/CoreFoundation.h>
#include "fishhook.h"
#include <map>
#include <mutex>

struct MethodHookInfo {
    void* klass;
    void* method_info;
};

static std::map<void*, MethodHookInfo> g_method_map;
static std::mutex g_method_map_mutex;

static std::map<void*, std::string> g_symbol_name_map;
static std::mutex g_symbol_name_map_mutex;

std::string GetiOSDocumentsDirectory() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    if (documentsDirectory) {
        return [documentsDirectory UTF8String];
    }
    return "";
}




static void* local_resolve_symbol(const char* symbol_name) {
    void* sym = dlsym(RTLD_DEFAULT, symbol_name);
    if (sym) {
        std::lock_guard<std::mutex> lock(g_symbol_name_map_mutex);
        g_symbol_name_map[sym] = symbol_name;
    }
    return sym;
}
#endif
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <deque>
#include <atomic>
#include "json.hpp"

using json = nlohmann::json;

#ifdef __APPLE__
std::vector<std::string> GetiOSLogPaths(const std::string& filename) {
    std::vector<std::string> paths;
    
    // 1. Documents Directory
    std::string docs = GetiOSDocumentsDirectory();
    if (!docs.empty()) {
        paths.push_back(docs + "/" + filename);
    }
    
    // 2. Library/Caches Directory
    NSArray *cachePaths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    NSString *cacheDir = [cachePaths firstObject];
    if (cacheDir) {
        paths.push_back(std::string([cacheDir UTF8String]) + "/" + filename);
    }
    
    // 3. tmp Directory
    NSString *tmpDir = NSTemporaryDirectory();
    if (tmpDir) {
        paths.push_back(std::string([tmpDir UTF8String]) + "/" + filename);
    }
    
    // 4. Sandbox Home directory environment fallbacks
    char* home = getenv("HOME");
    std::string home_str = home ? home : "";
    if (!home_str.empty()) {
        paths.push_back(home_str + "/Documents/" + filename);
        paths.push_back(home_str + "/Library/Caches/" + filename);
        paths.push_back(home_str + "/tmp/" + filename);
    }
    
    // 5. Default iOS standard paths
    paths.push_back("/var/mobile/Documents/" + filename);
    paths.push_back("/var/mobile/Containers/Data/Application/Documents/" + filename);
    
    return paths;
}

typedef SInt32 (*CFUserNotificationDisplayAlert_t)(
    CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL,
    CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage,
    CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle,
    CFOptionFlags *responseFlags);

static void ShowStartupAlert() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        void* addr = dlsym(RTLD_DEFAULT, "CFUserNotificationDisplayAlert");
        if (addr) {
            auto fn = (CFUserNotificationDisplayAlert_t)addr;
            fn(
                0.0,
                3, // kCFUserNotificationPlainAlertLevel value is 3
                NULL, NULL, NULL,
                CFSTR("Hachimi Packet-Capture"),
                CFSTR("Tweak startup succeeded!\nLogs are written to sandboxed Documents, Library/Caches, and tmp directories."),
                CFSTR("Awesome"),
                NULL, NULL, NULL
            );
        } else {
            NSLog(@"[Hachimi-PacketCapture] CFUserNotificationDisplayAlert symbol not found via dlsym.");
        }
    }).detach();
}
#endif


#ifdef _WIN32
#define HACHIMI_EXPORT extern "C" __declspec(dllexport)
#else
#define HACHIMI_EXPORT extern "C" __attribute__((visibility("default")))
#endif

typedef void* (*HachimiGetApiFn)(const char* name);

typedef void* (*hachimi_instance_t)();
typedef void* (*hachimi_get_interceptor_t)(void* hachimi);
typedef void* (*interceptor_hook_t)(void* interceptor, void* orig_addr, void* hook_addr);

typedef void* (*il2cpp_get_assembly_image_t)(const char* assembly_name);
typedef void* (*il2cpp_get_class_t)(void* image, const char* namespaze, const char* name);
typedef void* (*il2cpp_get_method_t)(void* klass, const char* name, int argsCount);
typedef void* (*il2cpp_get_method_addr_t)(void* klass, const char* name, int argsCount);
typedef void* (*il2cpp_resolve_symbol_t)(const char* name);

typedef void* (*il2cpp_string_new_t)(const char* text);
typedef uint16_t* (*il2cpp_string_chars_t)(void* str);
typedef int32_t (*il2cpp_string_length_t)(void* str);

typedef void (*hachimi_log_t)(int level, const char* tag, const char* message);
typedef const char* (*hachimi_get_data_path_t)();

static hachimi_log_t g_log = nullptr;
static hachimi_instance_t g_hachimi_instance = nullptr;
static hachimi_get_interceptor_t g_hachimi_get_interceptor = nullptr;
static interceptor_hook_t g_interceptor_hook = nullptr;
static hachimi_get_data_path_t g_get_data_path = nullptr;

static il2cpp_get_assembly_image_t g_get_assembly_image = nullptr;
static il2cpp_get_class_t g_get_class = nullptr;
static il2cpp_get_method_t g_get_method = nullptr;
static il2cpp_get_method_addr_t g_get_method_addr = nullptr;
static il2cpp_resolve_symbol_t g_resolve_symbol = nullptr;

static il2cpp_string_new_t g_string_new = nullptr;
static il2cpp_string_chars_t g_string_chars = nullptr;
static il2cpp_string_length_t g_string_length = nullptr;

static std::string g_outputDir;

// Configs
static bool g_capture_enabled = true;
static bool g_download_capture_enabled = true;

static thread_local std::vector<uint8_t> t_last_raw_request;
static std::mutex g_queue_mutex;
static std::deque<std::string> g_url_queue;
static std::atomic<int> g_req_seq(0);

static void Log(const std::string& msg) {
#ifdef __APPLE__
    NSLog(@"[Hachimi-PacketCapture] %s", msg.c_str());
    fprintf(stderr, "[Hachimi-PacketCapture] %s\n", msg.c_str());
    fflush(stderr);

    std::vector<std::string> paths = GetiOSLogPaths("capture.log");
    bool at_least_one_success = false;
    std::string last_error = "";
    
    for (const auto& path : paths) {
        std::ofstream ofs(path, std::ios::out | std::ios::app);
        if (ofs.is_open()) {
            ofs << msg << "\n";
            ofs.close();
            at_least_one_success = true;
        } else {
            last_error = strerror(errno);
        }
    }
    
    if (!at_least_one_success) {
        NSLog(@"[Hachimi-PacketCapture] ERROR: Failed to write file log to any location. Last error: %s", last_error.c_str());
    }
#else
    if (!g_outputDir.empty()) {
        std::string logPath = g_outputDir + "/capture.log";
        std::ofstream ofs(logPath, std::ios::out | std::ios::app);
        if (ofs.is_open()) {
            ofs << msg << "\n";
            ofs.close();
        }
    }
#endif
}

static std::string GetPackageName() {
    return "jp.co.cygames.umamusume";
}

static void EnsureDirectory(const std::string& path) {
    std::string current = "";
    for (char c : path) {
        current += c;
        if (c == '/' || c == '\\') {
#ifdef _WIN32
            _mkdir(current.c_str());
#else
            mkdir(current.c_str(), 0777);
#endif
        }
    }
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(current.c_str(), 0777);
#endif
}

static std::string GetPluginOutputDir(const char* plugin_dir) {
#ifdef _WIN32
    if (g_get_data_path) {
        const char* base = g_get_data_path();
        if (base && base[0] != '\0') {
            return std::string(base) + "/" + plugin_dir;
        }
    }
    return std::string(".") + "/" + plugin_dir;
#elif defined(__APPLE__)
    std::string docs = GetiOSDocumentsDirectory();
    if (!docs.empty()) {
        return docs;
    }
    char* home = getenv("HOME");
    std::string home_str = home ? home : "";
    if (home_str.empty()) {
        home_str = "/var/mobile";
    }
    return home_str + "/Documents";
#else
    return "/sdcard/Android/media/" + GetPackageName() + "/hachimi/" + plugin_dir;
#endif
}

static void ResolveStringFunctions() {
    if (!g_resolve_symbol) {
        Log("il2cpp_resolve_symbol API is unavailable.");
        return;
    }

    g_string_new = (il2cpp_string_new_t)g_resolve_symbol("il2cpp_string_new");
    g_string_chars = (il2cpp_string_chars_t)g_resolve_symbol("il2cpp_string_chars");
    g_string_length = (il2cpp_string_length_t)g_resolve_symbol("il2cpp_string_length");
}

static void DumpBuffer(const std::string& name, const void* data, size_t length) {
    if (!data || length == 0) return;
    
    try {
        std::vector<uint8_t> v((uint8_t*)data, (uint8_t*)data + length);
        json j = json::from_msgpack(v, true, false);
        
        if (!j.is_discarded()) {
            std::string filename = g_outputDir + "/" + name + ".json";
            std::ofstream out(filename);
            if (out.is_open()) {
                out << j.dump(4);
                out.close();
            }
            return;
        }
    } catch (...) {
        // Fallback to bin
    }
    
    std::string filename = g_outputDir + "/" + name + ".bin";
    std::ofstream out(filename, std::ios::binary);
    if (out.is_open()) {
        out.write((const char*)data, length);
        out.close();
    }
}

// Trampolines
typedef void* (*compress_req_t)(void* body, void* method_info);
typedef void* (*decompress_resp_t)(void* response, void* method_info);
typedef void* (*post_t)(void* this_ptr, void* url, void* postData, void* headers, void* method_info);

static compress_req_t o_CompressRequest = nullptr;
static decompress_resp_t o_DecompressResponse = nullptr;
static post_t o_Post = nullptr;

static void* h_CompressRequest(void* body, void* method_info) {
    if (g_capture_enabled && body) {
        int32_t length = *(int32_t*)((char*)body + sizeof(void*) * 3);
        char* data = (char*)body + sizeof(void*) * 4;
        if (length > 0 && length < (16 * 1024 * 1024)) {
            t_last_raw_request.assign((uint8_t*)data, (uint8_t*)data + length);
        }
    }
    return o_CompressRequest(body, method_info);
}

static void* h_DecompressResponse(void* response, void* method_info) {
    void* ret = o_DecompressResponse(response, method_info);
    if (g_capture_enabled && ret) {
        int32_t length = *(int32_t*)((char*)ret + sizeof(void*) * 3);
        char* data = (char*)ret + sizeof(void*) * 4;
        if (length > 0 && length < (16 * 1024 * 1024)) {
            std::string prefix = "unknown";
            {
                std::lock_guard<std::mutex> lock(g_queue_mutex);
                if (!g_url_queue.empty()) {
                    prefix = g_url_queue.front();
                    g_url_queue.pop_front();
                }
            }
            DumpBuffer(prefix + "_resp", data, length);
        }
    }
    return ret;
}

static void* h_Post(void* this_ptr, void* url_str, void* postData, void* headers, void* method_info) {
    if (!g_capture_enabled) return o_Post(this_ptr, url_str, postData, headers, method_info);
    std::string s_url;
    if (url_str && g_string_chars && g_string_length) {
        int32_t len = g_string_length(url_str);
        uint16_t* chars = g_string_chars(url_str);
        for (int i = 0; i < len; ++i) {
            if (chars[i] < 0x80) s_url += (char)chars[i];
        }
    }
    
    std::string path_name = "unknown";
    size_t p = s_url.find("/umamusume/");
    if (p != std::string::npos) {
        path_name = s_url.substr(p + 11); // skip /umamusume/
        for (char& c : path_name) {
            if (c == '/') c = '-';
            else if (c == '?' || c == '&' || c == '=') c = '+';
        }
    }
    
    static auto process_start_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int seq = ++g_req_seq;
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "%lld_%05d_%s", (long long)process_start_time, seq, path_name.c_str());
    std::string final_prefix = prefix;
    
    Log("Captured POST: " + s_url);
    
    // Dump the saved raw request
    if (!t_last_raw_request.empty()) {
        DumpBuffer(final_prefix + "_req", t_last_raw_request.data(), t_last_raw_request.size());
        t_last_raw_request.clear();
    }
    
    // Save for response
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        g_url_queue.push_back(final_prefix);
    }
    
    return o_Post(this_ptr, url_str, postData, headers, method_info);
}

typedef void* (*tempest_register_request_t)(void* this_ptr, int32_t* request_idx, void* body, void* method_info);
static tempest_register_request_t o_TempestRegisterRequest = nullptr;

static void* h_TempestRegisterRequest(void* this_ptr, int32_t* request_idx, void* body_ptr, void* method_info) {
    if (g_download_capture_enabled && body_ptr) {
        struct TempestRequestBody {
            int32_t id;
            int32_t padding;
            void* url;
            void* path;
            uint64_t size;
            uint64_t checksum;
            int32_t strategy;
            int32_t priority;
        };
        TempestRequestBody* body = (TempestRequestBody*)body_ptr;
        
        std::string s_url;
        if (body->url && g_string_chars && g_string_length) {
            int32_t len = g_string_length(body->url);
            uint16_t* chars = g_string_chars(body->url);
            for (int i = 0; i < len; ++i) if (chars[i] < 0x80) s_url += (char)chars[i];
        }
        
        std::string s_path;
        if (body->path && g_string_chars && g_string_length) {
            int32_t len = g_string_length(body->path);
            uint16_t* chars = g_string_chars(body->path);
            for (int i = 0; i < len; ++i) if (chars[i] < 0x80) s_path += (char)chars[i];
        }
        
        json j;
        j["id"] = body->id;
        j["url"] = s_url.empty() ? "<EMPTY_OR_NULL>" : s_url;
        j["path"] = s_path;
        j["size"] = body->size;
        j["checksum"] = body->checksum;
        j["strategy"] = body->strategy;
        j["priority"] = body->priority;
        
        std::string logLine = j.dump();
        
        std::string jsonPath = g_outputDir + "/downloads.jsonl";
        std::ofstream ofs(jsonPath, std::ios::out | std::ios::app);
        if (ofs.is_open()) {
            ofs << logLine << "\n";
            ofs.close();
        }
    }
    return o_TempestRegisterRequest(this_ptr, request_idx, body_ptr, method_info);
}

static void LoadConfig() {
    std::vector<std::string> configPaths;
#ifdef __APPLE__
    configPaths = GetiOSLogPaths("capture_config.json");
#else
    configPaths.push_back(g_outputDir + "/capture_config.json");
#endif

    bool config_loaded = false;
    for (const auto& configPath : configPaths) {
        std::ifstream ifs(configPath);
        if (ifs.is_open()) {
            try {
                json j;
                ifs >> j;
                g_capture_enabled = j.value("capture_enabled", true);
                g_download_capture_enabled = j.value("download_capture_enabled", true);
                Log("Config loaded from " + configPath + ". Normal Capture: " + std::to_string(g_capture_enabled) + 
                    ", Download Capture: " + std::to_string(g_download_capture_enabled));
                config_loaded = true;
                break;
            } catch (const std::exception& e) {
                Log("Failed to parse config at " + configPath + ": " + std::string(e.what()));
            }
        }
    }

    if (!config_loaded) {
        json j;
        j["capture_enabled"] = true;
        j["download_capture_enabled"] = true;
        
        for (const auto& configPath : configPaths) {
            std::ofstream ofs(configPath);
            if (ofs.is_open()) {
                ofs << j.dump(4);
                ofs.close();
                Log("Default config created at " + configPath);
            }
        }
    }
}

static void OnGameInitialized() {
    Log("Game initialized, setting up capture hooks...");
    LoadConfig();
    
    ResolveStringFunctions();

    if (!g_string_new || !g_string_chars || !g_string_length) {
        Log("Failed to resolve string manipulation functions from il2cpp.");
    }

    void* image_uma = g_get_assembly_image("umamusume.dll");
    if (image_uma) {
        void* klass_http = g_get_class(image_uma, "Gallop", "HttpHelper");
        if (klass_http) {
            void* a_compress = g_get_method_addr(klass_http, "CompressRequest", 1);
            void* a_decompress = g_get_method_addr(klass_http, "DecompressResponse", 1);
            
            if (a_compress && a_decompress) {
                void* hachimi = g_hachimi_instance();
                void* interceptor = g_hachimi_get_interceptor(hachimi);
                o_CompressRequest = (compress_req_t)g_interceptor_hook(interceptor, a_compress, (void*)h_CompressRequest);
                o_DecompressResponse = (decompress_resp_t)g_interceptor_hook(interceptor, a_decompress, (void*)h_DecompressResponse);
                Log("Gallop.HttpHelper hooks installed.");
            }
        }
    }
    
    void* image_cute = g_get_assembly_image("Cute.Http.Assembly.dll");
    if (image_cute) {
        void* klass_www = g_get_class(image_cute, "Cute.Http", "WWWRequest");
        if (klass_www) {
            void* a_post = g_get_method_addr(klass_www, "Post", 3);
            if (a_post) {
                void* hachimi = g_hachimi_instance();
                void* interceptor = g_hachimi_get_interceptor(hachimi);
                o_Post = (post_t)g_interceptor_hook(interceptor, a_post, (void*)h_Post);
                Log("Cute.Http.WWWRequest.Post hook installed.");
            }
        }
    }

    void* image_libnative = g_get_assembly_image("LibNative.Runtime.dll");
    if (image_libnative) {
        void* klass_downloader = g_get_class(image_libnative, "LibNative.Tempest", "Downloader");
        if (klass_downloader) {
            void* a_register_req = g_get_method_addr(klass_downloader, "RegisterRequest", 2);
            if (a_register_req) {
                void* hachimi = g_hachimi_instance();
                void* interceptor = g_hachimi_get_interceptor(hachimi);
                o_TempestRegisterRequest = (tempest_register_request_t)g_interceptor_hook(interceptor, a_register_req, (void*)h_TempestRegisterRequest);
                Log("LibNative.Tempest.Downloader.RegisterRequest hook installed.");
            }
        }
    }
}

static std::atomic<bool> g_il2cpp_initialized{false};

static void HookThread() {
    Log("HookThread started.");
    int counter = 0;
    while (true) {
        if (!g_il2cpp_initialized.load()) {
            typedef void* (*il2cpp_domain_get_t)();
            static il2cpp_domain_get_t f_domain_get = nullptr;
            if (!f_domain_get) f_domain_get = (il2cpp_domain_get_t)dlsym(RTLD_DEFAULT, "il2cpp_domain_get");
            if (f_domain_get) {
                void* dom = f_domain_get();
                if (dom) {
                    g_il2cpp_initialized.store(true);
                    Log("IL2CPP domain detected initialized via fallback check!");
                }
            }
        }

        if (g_il2cpp_initialized.load()) {
            if (g_get_assembly_image) {
                void* image_uma = g_get_assembly_image("umamusume.dll");
                if (!image_uma) {
                    image_uma = g_get_assembly_image("umamusume");
                }
                if (image_uma) {
                    Log("Found umamusume assembly image!");
                    break;
                }
            }
        }
        if (counter++ % 100 == 0) {
            char temp[256];
            snprintf(temp, sizeof(temp), "HookThread still waiting for umamusume.dll... (ticks: %d, il2cpp_initialized: %d)", counter, (int)g_il2cpp_initialized.load());
            Log(temp);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    OnGameInitialized();
}

static bool g_standalone_initialized = false;

HACHIMI_EXPORT bool hachimi_init_v3(HachimiGetApiFn get_api, int version) {
    g_standalone_initialized = true;
    g_log = (hachimi_log_t)get_api("log");
    g_hachimi_instance = (hachimi_instance_t)get_api("hachimi_instance");
    g_hachimi_get_interceptor = (hachimi_get_interceptor_t)get_api("hachimi_get_interceptor");
    g_interceptor_hook = (interceptor_hook_t)get_api("interceptor_hook");
    g_get_data_path = (hachimi_get_data_path_t)get_api("hachimi_get_data_path");
    
    g_get_assembly_image = (il2cpp_get_assembly_image_t)get_api("il2cpp_get_assembly_image");
    g_get_class = (il2cpp_get_class_t)get_api("il2cpp_get_class");
    g_get_method = (il2cpp_get_method_t)get_api("il2cpp_get_method");
    g_get_method_addr = (il2cpp_get_method_addr_t)get_api("il2cpp_get_method_addr");
    g_resolve_symbol = (il2cpp_resolve_symbol_t)get_api("il2cpp_resolve_symbol");
    
    g_outputDir = GetPluginOutputDir("PacketCapture");
    EnsureDirectory(g_outputDir);
    
    Log("Packet-Capture Plugin Initialized! Output Dir: " + g_outputDir);
    
    std::thread(HookThread).detach();
    
    return true;
}

#ifdef __APPLE__
static void* local_get_assembly_image(const char* assembly_name) {
    typedef void* (*il2cpp_domain_get_t)();
    typedef void* (*il2cpp_domain_assembly_open_t)(void* domain, const char* name);
    typedef void* (*il2cpp_assembly_get_image_t)(void* assembly);

    static il2cpp_domain_get_t f_il2cpp_domain_get = nullptr;
    static il2cpp_domain_assembly_open_t f_il2cpp_domain_assembly_open = nullptr;
    static il2cpp_assembly_get_image_t f_il2cpp_assembly_get_image = nullptr;

    if (!f_il2cpp_domain_get) f_il2cpp_domain_get = (il2cpp_domain_get_t)local_resolve_symbol("il2cpp_domain_get");
    if (!f_il2cpp_domain_assembly_open) f_il2cpp_domain_assembly_open = (il2cpp_domain_assembly_open_t)local_resolve_symbol("il2cpp_domain_assembly_open");
    if (!f_il2cpp_assembly_get_image) f_il2cpp_assembly_get_image = (il2cpp_assembly_get_image_t)local_resolve_symbol("il2cpp_assembly_get_image");

    static bool symbols_logged = false;
    if (!symbols_logged && f_il2cpp_domain_get && f_il2cpp_domain_assembly_open && f_il2cpp_assembly_get_image) {
        char temp[512];
        snprintf(temp, sizeof(temp), "Local IL2CPP functions resolved: domain_get=%p, assembly_open=%p, assembly_get_image=%p",
                 f_il2cpp_domain_get, f_il2cpp_domain_assembly_open, f_il2cpp_assembly_get_image);
        Log(temp);
        symbols_logged = true;
    }

    if (!f_il2cpp_domain_get || !f_il2cpp_domain_assembly_open || !f_il2cpp_assembly_get_image) return nullptr;

    void* domain = f_il2cpp_domain_get();
    if (!domain) return nullptr;
    void* assembly = f_il2cpp_domain_assembly_open(domain, assembly_name);
    if (!assembly) return nullptr;
    return f_il2cpp_assembly_get_image(assembly);
}

static void* local_get_class(void* image, const char* namespaze, const char* name) {
    typedef void* (*il2cpp_class_from_name_t)(void* image, const char* namespaze, const char* name);
    static il2cpp_class_from_name_t f_il2cpp_class_from_name = nullptr;
    if (!f_il2cpp_class_from_name) f_il2cpp_class_from_name = (il2cpp_class_from_name_t)local_resolve_symbol("il2cpp_class_from_name");
    if (!f_il2cpp_class_from_name) return nullptr;
    return f_il2cpp_class_from_name(image, namespaze, name);
}

static void* local_get_method_addr(void* klass, const char* name, int argsCount) {
    typedef void* (*il2cpp_class_get_method_from_name_t)(void* klass, const char* name, int argsCount);
    static il2cpp_class_get_method_from_name_t f_il2cpp_class_get_method_from_name = nullptr;
    if (!f_il2cpp_class_get_method_from_name) f_il2cpp_class_get_method_from_name = (il2cpp_class_get_method_from_name_t)local_resolve_symbol("il2cpp_class_get_method_from_name");
    if (!f_il2cpp_class_get_method_from_name) return nullptr;
    void* method = f_il2cpp_class_get_method_from_name(klass, name, argsCount);
    if (!method) return nullptr;
    
    void* method_ptr = *(void**)method;
    if (method_ptr) {
        std::lock_guard<std::mutex> lock(g_method_map_mutex);
        g_method_map[method_ptr] = { klass, method };
    }
    return method_ptr;
}

static void* local_interceptor_hook(void* interceptor, void* orig_addr, void* hook_addr) {
    if (!orig_addr || !hook_addr) return nullptr;

    // 1. Check if it's a registered IL2CPP method
    void* klass = nullptr;
    void* method_info = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_method_map_mutex);
        auto it = g_method_map.find(orig_addr);
        if (it != g_method_map.end()) {
            klass = it->second.klass;
            method_info = it->second.method_info;
        }
    }

    if (klass && method_info) {
        // Force class initialization if possible to populate vtable
        typedef void (*il2cpp_runtime_class_init_t)(void* klass);
        static il2cpp_runtime_class_init_t f_il2cpp_runtime_class_init = nullptr;
        if (!f_il2cpp_runtime_class_init) f_il2cpp_runtime_class_init = (il2cpp_runtime_class_init_t)local_resolve_symbol("il2cpp_runtime_class_init");
        if (f_il2cpp_runtime_class_init) {
            f_il2cpp_runtime_class_init(klass);
        }

        // Patch MethodInfo pointer
        void** methodPointer_ptr = (void**)method_info;
        void** virtualMethodPointer_ptr = ((void**)method_info) + 1;
        *methodPointer_ptr = hook_addr;
        *virtualMethodPointer_ptr = hook_addr;

        // Scan Class memory to patch matching VirtualInvokeData vtable entries
        char* klass_bytes = (char*)klass;
        int scan_start = 0x80;
        int scan_end = 0x800; // scan up to 2048 bytes
        int replaced_count = 0;
        for (int offset = scan_start; offset <= scan_end - 16; offset += 8) {
            void** ptr = (void**)(klass_bytes + offset);
            if (*ptr == orig_addr && *(ptr + 1) == method_info) {
                *ptr = hook_addr;
                replaced_count++;
            }
        }
        Log("Hijacked MethodInfo & VTable. VTable patched " + std::to_string(replaced_count) + " times.");
        return orig_addr;
    }

    // 2. Check if it's a native C symbol resolved via ResolveNativeSymbol
    std::string sym_name;
    {
        std::lock_guard<std::mutex> lock(g_symbol_name_map_mutex);
        auto it = g_symbol_name_map.find(orig_addr);
        if (it != g_symbol_name_map.end()) {
            sym_name = it->second;
        }
    }

    if (!sym_name.empty()) {
        struct rebinding rebs[1];
        rebs[0].name = sym_name.c_str();
        rebs[0].replacement = hook_addr;
        
        void* orig_temp = nullptr;
        rebs[0].replaced = &orig_temp;
        
        rebind_symbols(rebs, 1);
        Log("Native C symbol hijacked via fishhook: " + sym_name + " [Original: " + std::to_string((uintptr_t)orig_temp) + "]");
        return orig_temp;
    }

    Log("local_interceptor_hook: Failed to hijack target address (neither method nor symbol found).");
    return nullptr;
}

typedef bool (*il2cpp_init_t)(const char* domain_name);
static il2cpp_init_t o_il2cpp_init = nullptr;

static void StartHookThreadOnce() {
    static std::atomic<bool> started{false};
    if (started.exchange(true)) return;
    std::thread(HookThread).detach();
}

static bool h_il2cpp_init(const char* domain_name) {
    Log("h_il2cpp_init called!");
    g_get_assembly_image = local_get_assembly_image;
    g_get_class = local_get_class;
    g_get_method_addr = local_get_method_addr;
    g_resolve_symbol = local_resolve_symbol;
    g_interceptor_hook = local_interceptor_hook;

    g_outputDir = GetPluginOutputDir("PacketCapture");
    EnsureDirectory(g_outputDir);

    Log("Standalone iOS Tweak Mode (JIT-less) Initialized! Directory: " + g_outputDir);

    bool ret = o_il2cpp_init(domain_name);
    g_il2cpp_initialized.store(true);

    StartHookThreadOnce();

    return ret;
}

#ifdef __APPLE__
#include <mach-o/dyld.h>
static void LogFrameworkStatus() {
    uint32_t count = _dyld_image_count();
    bool found_unity = false;
    bool found_game_assembly = false;
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (name) {
            std::string s_name(name);
            if (s_name.find("UnityFramework") != std::string::npos) {
                found_unity = true;
            }
            if (s_name.find("GameAssembly") != std::string::npos) {
                found_game_assembly = true;
            }
        }
    }
    Log("Framework Status at load time: UnityFramework=" + std::to_string(found_unity) + 
        ", GameAssembly=" + std::to_string(found_game_assembly));
}
#endif

__attribute__((constructor)) static void ios_tweak_init() {
    if (g_standalone_initialized) return;
    g_standalone_initialized = true;

    g_outputDir = GetPluginOutputDir("PacketCapture");
    Log("=========================================");
    Log("Hachimi Packet-Capture Tweak Dylib Constructor Loaded!");
    Log("=========================================");
    ShowStartupAlert();
#ifdef __APPLE__
    LogFrameworkStatus();

    // Register notification observer for launch completion
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        Log("UIApplicationDidFinishLaunchingNotification received! Setting il2cpp_initialized = true.");
        g_il2cpp_initialized.store(true);
    }];
#endif

    g_get_assembly_image = local_get_assembly_image;
    g_get_class = local_get_class;
    g_get_method_addr = local_get_method_addr;
    g_resolve_symbol = local_resolve_symbol;
    g_interceptor_hook = local_interceptor_hook;

    StartHookThreadOnce();

    struct rebinding rebs[1];
    rebs[0].name = "il2cpp_init";
    rebs[0].replacement = (void*)h_il2cpp_init;
    rebs[0].replaced = (void**)&o_il2cpp_init;

    int res = rebind_symbols(rebs, 1);
    char temp[256];
    snprintf(temp, sizeof(temp), "Registered il2cpp_init hook via fishhook. Result: %d", res);
    Log(temp);
}
#endif
