#if defined(__ANDROID__) || defined(__APPLE__)
#include <dlfcn.h>
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
    if (!g_outputDir.empty()) {
        std::string logPath = g_outputDir + "/proxy.log";
        std::ofstream ofs(logPath, std::ios::out | std::ios::app);
        if (ofs.is_open()) {
            ofs << msg << "\n";
            ofs.close();
        }
    }
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
    char* home = getenv("HOME");
    std::string home_str = home ? home : "";
    if (home_str.empty()) {
        home_str = "/var/mobile";
    }
    return home_str + "/Documents/hachimi/" + plugin_dir;
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
    void* sym = dlsym(RTLD_DEFAULT, symbol_name);
    if (sym) return sym;
    void* handle = dlopen(nullptr, RTLD_LAZY);
    sym = handle ? dlsym(handle, symbol_name) : nullptr;
    if (handle) dlclose(handle);
    return sym;
#else
    (void)module_name;
    (void)symbol_name;
    return nullptr;
#endif
}

static void LoadConfig() {
    std::string configPath = g_outputDir + "/config.json";
    std::ifstream ifs(configPath);
    if (ifs.is_open()) {
        try {
            json j;
            ifs >> j;
            g_proxy_enabled = j.value("proxy_enabled", false);
            g_proxy_url = j.value("proxy_url", "http://127.0.0.1:5090");
            Log("Config loaded. Proxy Enabled: " + std::to_string(g_proxy_enabled) + ", Target: " + g_proxy_url);
        } catch (const std::exception& e) {
            Log("Failed to parse config: " + std::string(e.what()));
        }
    } else {
        json j;
        j["proxy_enabled"] = false;
        j["proxy_url"] = "http://127.0.0.1:5090";
        std::ofstream ofs(configPath);
        if (ofs.is_open()) {
            ofs << j.dump(4);
            ofs.close();
            Log("Default config created.");
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
    while (true) {
        if (g_get_assembly_image) {
            void* image_uma = g_get_assembly_image("umamusume.dll");
            if (image_uma) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
#include <tinyhook.h>

static void* local_resolve_symbol(const char* symbol_name) {
    return dlsym(RTLD_DEFAULT, symbol_name);
}

static void* local_get_assembly_image(const char* assembly_name) {
    typedef void* (*il2cpp_domain_get_t)();
    typedef void* (*il2cpp_domain_assembly_open_t)(void* domain, const char* name);
    typedef void* (*il2cpp_assembly_get_image_t)(void* assembly);

    static il2cpp_domain_get_t f_il2cpp_domain_get = (il2cpp_domain_get_t)local_resolve_symbol("il2cpp_domain_get");
    static il2cpp_domain_assembly_open_t f_il2cpp_domain_assembly_open = (il2cpp_domain_assembly_open_t)local_resolve_symbol("il2cpp_domain_assembly_open");
    static il2cpp_assembly_get_image_t f_il2cpp_assembly_get_image = (il2cpp_assembly_get_image_t)local_resolve_symbol("il2cpp_assembly_get_image");

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
    return *(void**)method;
}

static void* local_interceptor_hook(void* interceptor, void* orig_addr, void* hook_addr) {
    void* orig = nullptr;
    if (tiny_hook(orig_addr, hook_addr, &orig) == 0) {
        return orig;
    }
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

    Log("Standalone iOS Tweak Mode Initialized! Directory: " + g_outputDir);

    bool ret = o_il2cpp_init(domain_name);

    std::thread(HookThread).detach();

    return ret;
}

__attribute__((constructor)) static void ios_tweak_init() {
    if (g_standalone_initialized) return;
    g_standalone_initialized = true;

    void* init_addr = dlsym(RTLD_DEFAULT, "il2cpp_init");
    if (init_addr) {
        tiny_hook(init_addr, (void*)h_il2cpp_init, (void**)&o_il2cpp_init);
    }
}
#endif
