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
    include(FetchContent)
    FetchContent_Declare(
      dobby
      GIT_REPOSITORY https://github.com/jmpews/Dobby.git
      GIT_TAG        master
    )
    set(DOBBY_GENERATE_SHARED OFF CACHE BOOL "Build dobby static" FORCE)
    FetchContent_MakeAvailable(dobby)
    target_link_libraries(uma_proxy PRIVATE dobby_static)
endif()

if(MSVC)
    target_compile_options(uma_proxy PRIVATE /EHsc)
else()
    target_compile_options(uma_proxy PRIVATE -fexceptions)
    set_property(TARGET uma_proxy APPEND_STRING PROPERTY LINK_FLAGS " -s")
endif()
