cmake_minimum_required(VERSION 3.11)
project(PacketCapturePlugin LANGUAGES C CXX)

if(APPLE)
    enable_language(OBJCXX)
endif()

add_library(packet_capture SHARED
    src/main.cxx
)

target_compile_features(packet_capture PRIVATE cxx_std_17)

if(ANDROID)
    target_link_libraries(packet_capture log dl)
endif()

if(APPLE)
    target_sources(packet_capture PRIVATE src/fishhook.c)
    set_source_files_properties(src/main.cxx PROPERTIES LANGUAGE OBJCXX)
    target_link_libraries(packet_capture PRIVATE "-framework Foundation")
endif()

if(MSVC)
    target_compile_options(packet_capture PRIVATE /EHsc)
else()
    target_compile_options(packet_capture PRIVATE -fexceptions -fvisibility=hidden)
    set_property(TARGET packet_capture APPEND_STRING PROPERTY LINK_FLAGS " -s")
endif()
