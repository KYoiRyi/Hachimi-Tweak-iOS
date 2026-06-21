cmake_minimum_required(VERSION 3.11)
project(Uma-ProxyPlugin LANGUAGES CXX)

add_library(uma_proxy SHARED
    src/main.cxx
)

target_compile_features(uma_proxy PRIVATE cxx_std_17)

if(ANDROID)
    target_link_libraries(uma_proxy log dl)
endif()

if(APPLE)
    target_sources(uma_proxy PRIVATE src/fishhook.c)
    set_source_files_properties(src/main.cxx PROPERTIES COMPILE_FLAGS "-x objective-c++")
    target_link_libraries(uma_proxy PRIVATE "-framework Foundation")
endif()

if(MSVC)
    target_compile_options(uma_proxy PRIVATE /EHsc)
else()
    target_compile_options(uma_proxy PRIVATE -fexceptions -fvisibility=hidden)
    set_property(TARGET uma_proxy APPEND_STRING PROPERTY LINK_FLAGS " -s")
endif()
