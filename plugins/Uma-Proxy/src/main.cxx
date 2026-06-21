#if defined(__ANDROID__) || defined(__APPLE__)
#include <dlfcn.h>
#endif
#ifdef __APPLE__
#import <Foundation/Foundation.h>
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

#ifdef __APPLE__
static void ShowStartupAlert() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        CFUserNotificationDisplayAlert(
            0.0, // timeout
            kCFUserNotificationPlainAlertLevel, // flags
            NULL, // icon URL
            NULL, // sound URL
            NULL, // localization URL
            CFSTR("Hachimi Uma-Proxy"), // alertHeader
            CFSTR("Tweak startup succeeded!\nLogs are written to sandboxed Documents, Library/Caches, and tmp directories."), // alertMessage
            CFSTR("Awesome"), // defaultButtonTitle
            NULL, // alternateButtonTitle
            NULL, // otherButtonTitle
            NULL  // responseFlags
        );
    }).detach();
}
#endif


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
#include <windows.h>
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
#include "json.hpp"

using json = nlohmann::json;

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
static bool g_proxy_enabled = false;
static std::string g_proxy_url = "http://127.0.0.1:5090";

static void Log(const std::string& msg) {
#ifdef __APPLE__
    NSLog(@"[Hachimi-UmaProxy] %s", msg.c_str());
    fprintf(stderr, "[Hachimi-UmaProxy] %s\n", msg.c_str());
    fflush(stderr);

    std::vector<std::string> paths = GetiOSLogPaths("proxy.log");
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
        NSLog(@"[Hachimi-UmaProxy] ERROR: Failed to write file log to any location. Last error: %s", last_error.c_str());
    }
#else
    if (!g_outputDir.empty()) {
        std::string logPath = g_outputDir + "/proxy.log";
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
    mkdir(path.c_str(), 0777);
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

static void* ResolveNativeSymbol(const char* module_name, const char* symbol_name) {
#if defined(__ANDROID__)
    void* handle = dlopen(module_name, RTLD_LAZY);
    return handle ? dlsym(handle, symbol_name) : nullptr;
#elif defined(_WIN32)
    HMODULE module = GetModuleHandleA(module_name);
    return module ? (void*)GetProcAddress(module, symbol_name) : nullptr;
#elif defined(__APPLE__)
    void* sym = local_resolve_symbol(symbol_name);
    if (sym) return sym;
    void* handle = dlopen(nullptr, RTLD_LAZY);
    sym = handle ? dlsym(handle, symbol_name) : nullptr;
    if (handle) dlclose(handle);
    if (sym) {
        std::lock_guard<std::mutex> lock(g_symbol_name_map_mutex);
        g_symbol_name_map[sym] = symbol_name;
    }
    return sym;
#else
    (void)module_name;
    (void)symbol_name;
    return nullptr;
#endif
}

static void LoadConfig() {
    std::vector<std::string> configPaths;
#ifdef __APPLE__
    configPaths = GetiOSLogPaths("config.json");
#else
    configPaths.push_back(g_outputDir + "/config.json");
#endif

    bool config_loaded = false;
    for (const auto& configPath : configPaths) {
        std::ifstream ifs(configPath);
        if (ifs.is_open()) {
            try {
                json j;
                ifs >> j;
                g_proxy_enabled = j.value("proxy_enabled", false);
                g_proxy_url = j.value("proxy_url", "http://127.0.0.1:5090");
                Log("Config loaded from " + configPath + ". Proxy Enabled: " + std::to_string(g_proxy_enabled) + ", Target: " + g_proxy_url);
                config_loaded = true;
                break;
            } catch (const std::exception& e) {
                Log("Failed to parse config at " + configPath + ": " + std::string(e.what()));
            }
        }
    }

    if (!config_loaded) {
        json j;
        j["proxy_enabled"] = false;
        j["proxy_url"] = "http://127.0.0.1:5090";
        
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

// Trampolines
typedef void* (*compress_req_t)(void* body, void* method_info);
typedef void* (*decompress_resp_t)(void* response, void* method_info);
typedef void* (*post_t)(void* this_ptr, void* url, void* postData, void* headers, void* method_info);

static compress_req_t o_CompressRequest = nullptr;
static decompress_resp_t o_DecompressResponse = nullptr;
static post_t o_Post = nullptr;

static void* h_CompressRequest(void* body, void* method_info) {
    if (g_proxy_enabled) {
        return body; // Bypass compression, return plaintext MsgPack
    }
    return o_CompressRequest(body, method_info);
}

static void* h_DecompressResponse(void* response, void* method_info) {
    if (g_proxy_enabled) {
        return response; // Bypass decompression, response is already plaintext MsgPack
    }
    return o_DecompressResponse(response, method_info);
}

typedef int (*curl_setopt_t)(void* curl, int option, void* param);
static curl_setopt_t o_curl_setopt = nullptr;

static int h_curl_setopt(void* curl, int option, void* param) {
    if (option == 10002 && param) { // CURLOPT_URL
        const char* u = (const char*)param;
        std::string s_url(u);
        size_t p = s_url.find("/umamusume/");
        if (g_proxy_enabled && p != std::string::npos) {
            std::string path = (p != std::string::npos) ? s_url.substr(p) : "/";
            std::string new_url_s = g_proxy_url + path;
            Log("[CURL-HOOK-SUCCESS] Intercepted URL: " + s_url + " -> " + new_url_s);
            
            // Allocate static buffer for thread-safe temporary string
            static thread_local char rb[1024];
            snprintf(rb, sizeof(rb), "%s", new_url_s.c_str());
            return o_curl_setopt(curl, option, (void*)rb);
        }
        Log("[CURL-HOOK-IGNORED] Passed original URL: " + s_url);
    }
    return o_curl_setopt(curl, option, param);
}

static void* h_Post(void* this_ptr, void* url_str, void* postData, void* headers, void* method_info) {
    if (!url_str || !g_string_chars || !g_string_length) {
        return o_Post(this_ptr, url_str, postData, headers, method_info);
    }
    
    int32_t len = g_string_length(url_str);
    uint16_t* chars = g_string_chars(url_str);
    std::string s_url;
    for (int i = 0; i < len; ++i) if (chars[i] < 0x80) s_url += (char)chars[i];
    
    size_t p = s_url.find("/umamusume/");
    if (g_proxy_enabled && p != std::string::npos) {
        std::string path = (p != std::string::npos) ? s_url.substr(p) : "/";
        std::string new_url_s = g_proxy_url + path;
        Log("[IL2CPP-HOOK-SUCCESS] Intercepted POST: " + s_url + " -> " + new_url_s);
        void* new_url = g_string_new(new_url_s.c_str());
        return o_Post(this_ptr, new_url, postData, headers, method_info);
    }
    
    Log("[IL2CPP-HOOK-IGNORED] Passed original POST: " + s_url);
    return o_Post(this_ptr, url_str, postData, headers, method_info);
}

static void OnGameInitialized() {
    Log("Game initialized, setting up proxy hooks...");
    
    LoadConfig();

    ResolveStringFunctions();

    if (!g_string_new || !g_string_chars || !g_string_length) {
        Log("Failed to resolve string manipulation functions from il2cpp.");
    }
    
    // 1. Hook Compress/Decompress
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
            } else {
                Log("Failed to find CompressRequest or DecompressResponse addresses.");
            }
        }
    }
    
    // 2. Hook Cute.Http.WWWRequest.Post
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
            } else {
                Log("Failed to find WWWRequest.Post address.");
            }
        } else {
            Log("Failed to find Cute.Http.WWWRequest.");
        }
    } else {
        Log("Failed to get Cute.Http.Assembly.dll image.");
    }
    
    // 3. Low-level curl_easy_setopt hook (fallback/native level)
    void* curl_sym = ResolveNativeSymbol(
#ifdef _WIN32
        "GameAssembly.dll",
#else
        "libil2cpp.so",
#endif
        "curl_easy_setopt"
    );
    if (curl_sym) {
        void* hachimi = g_hachimi_instance();
        void* interceptor = g_hachimi_get_interceptor(hachimi);
        o_curl_setopt = (curl_setopt_t)g_interceptor_hook(interceptor, curl_sym, (void*)h_curl_setopt);
        Log("curl_easy_setopt hook installed.");
    } else {
        Log("curl_easy_setopt symbol not found; native fallback hook skipped.");
    }
}

static void HookThread() {
    Log("HookThread started.");
    int counter = 0;
    while (true) {
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
        if (counter++ % 100 == 0) {
            char temp[256];
            snprintf(temp, sizeof(temp), "HookThread still waiting for umamusume.dll... (ticks: %d)", counter);
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
    
    g_outputDir = GetPluginOutputDir("UmaProxy");
    EnsureDirectory(g_outputDir);
    
    Log("Uma-Proxy Plugin Initialized! Directory: " + g_outputDir);
    
    std::thread(HookThread).detach();
    
    return true;
}

#ifdef __APPLE__
static void* local_get_assembly_image(const char* assembly_name) {
    typedef void* (*il2cpp_domain_get_t)();
    typedef void* (*il2cpp_domain_assembly_open_t)(void* domain, const char* name);
    typedef void* (*il2cpp_assembly_get_image_t)(void* assembly);

    static il2cpp_domain_get_t f_il2cpp_domain_get = (il2cpp_domain_get_t)local_resolve_symbol("il2cpp_domain_get");
    static il2cpp_domain_assembly_open_t f_il2cpp_domain_assembly_open = (il2cpp_domain_assembly_open_t)local_resolve_symbol("il2cpp_domain_assembly_open");
    static il2cpp_assembly_get_image_t f_il2cpp_assembly_get_image = (il2cpp_assembly_get_image_t)local_resolve_symbol("il2cpp_assembly_get_image");

    static bool symbols_logged = false;
    if (!symbols_logged) {
        char temp[512];
        snprintf(temp, sizeof(temp), "Local IL2CPP functions: domain_get=%p, assembly_open=%p, assembly_get_image=%p",
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
    static il2cpp_class_from_name_t f_il2cpp_class_from_name = (il2cpp_class_from_name_t)local_resolve_symbol("il2cpp_class_from_name");
    if (!f_il2cpp_class_from_name) return nullptr;
    return f_il2cpp_class_from_name(image, namespaze, name);
}

static void* local_get_method_addr(void* klass, const char* name, int argsCount) {
    typedef void* (*il2cpp_class_get_method_from_name_t)(void* klass, const char* name, int argsCount);
    static il2cpp_class_get_method_from_name_t f_il2cpp_class_get_method_from_name = (il2cpp_class_get_method_from_name_t)local_resolve_symbol("il2cpp_class_get_method_from_name");
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
        static il2cpp_runtime_class_init_t f_il2cpp_runtime_class_init = (il2cpp_runtime_class_init_t)local_resolve_symbol("il2cpp_runtime_class_init");
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

static bool h_il2cpp_init(const char* domain_name) {
    g_get_assembly_image = local_get_assembly_image;
    g_get_class = local_get_class;
    g_get_method_addr = local_get_method_addr;
    g_resolve_symbol = local_resolve_symbol;
    g_interceptor_hook = local_interceptor_hook;

    g_outputDir = GetPluginOutputDir("UmaProxy");
    EnsureDirectory(g_outputDir);

    Log("Standalone iOS Tweak Mode (JIT-less) Initialized! Directory: " + g_outputDir);

    bool ret = o_il2cpp_init(domain_name);

    std::thread(HookThread).detach();

    return ret;
}

__attribute__((constructor)) static void ios_tweak_init() {
    if (g_standalone_initialized) return;
    g_standalone_initialized = true;

    g_outputDir = GetPluginOutputDir("UmaProxy");
    Log("=========================================");
    Log("Hachimi Uma-Proxy Tweak Dylib Constructor Loaded!");
    Log("=========================================");
    ShowStartupAlert();

    void* init_addr = dlsym(RTLD_DEFAULT, "il2cpp_init");
    if (init_addr) {
        struct rebinding rebs[1];
        rebs[0].name = "il2cpp_init";
        rebs[0].replacement = (void*)h_il2cpp_init;
        rebs[0].replaced = (void**)&o_il2cpp_init;

        rebind_symbols(rebs, 1);
        Log("Hooked il2cpp_init via fishhook!");
    } else {
        Log("ERROR: il2cpp_init symbol not found in process!");
    }
}
#endif
