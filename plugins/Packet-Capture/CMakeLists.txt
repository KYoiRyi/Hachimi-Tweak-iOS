cmake_minimum_required(VERSION 3.11)
project(PacketCapturePlugin LANGUAGES CXX)

add_library(packet_capture SHARED
    src/main.cxx
)

target_compile_features(packet_capture PRIVATE cxx_std_17)

if(ANDROID)
    target_link_libraries(packet_capture log dl)
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
    target_link_libraries(packet_capture PRIVATE dobby_static)
endif()

if(MSVC)
    target_compile_options(packet_capture PRIVATE /EHsc)
else()
    target_compile_options(packet_capture PRIVATE -fexceptions)
    set_property(TARGET packet_capture APPEND_STRING PROPERTY LINK_FLAGS " -s")
endif()
