# CMakeList.txt : CMake project for PageMonitor, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif ()

project(PageMonitor)

option(CAPSTONE_X86_SUPPORT "Enable x86 capstone" ON)


add_executable(${PROJECT_NAME} ${SRC}
        src/main.cpp
        src/syscalls.cpp
        src/nt.cpp
        src/nt.x64.asm
        src/dumper.cpp
        src/sections.cpp
)

# capstone
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/Dependencies/Capstone")

target_include_directories(${PROJECT_NAME} PRIVATE "include")
target_include_directories(${PROJECT_NAME} PRIVATE "Dependencies")

target_link_libraries(${PROJECT_NAME} PUBLIC
        capstone
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 23)
endif ()

if (WIN32)
    enable_language(ASM_MASM)
    set_source_files_properties(nt.asm PROPERTIES LANGUAGE ASM_MASM)
endif ()

