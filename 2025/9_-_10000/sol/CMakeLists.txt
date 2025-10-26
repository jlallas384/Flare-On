cmake_minimum_required(VERSION 4.0)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)


add_subdirectory(pe-parse)
add_subdirectory(json)
add_subdirectory(capstone)

add_library(common INTERFACE)

target_link_libraries(common INTERFACE pe-parse::pe-parse nlohmann_json::nlohmann_json capstone_static)
target_compile_definitions(common INTERFACE BASEDIR="${CMAKE_SOURCE_DIR}/..")


add_subdirectory(src)