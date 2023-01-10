cmake_minimum_required(VERSION 3.5)

project(certctl LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

set(SRCDIR src)

set(SRC ${SRCDIR}/main.cc
    ${SRCDIR}/store.cc
    ${SRCDIR}/utils.cc
    ${SRCDIR}/callback.cc
    ${SRCDIR}/cert.cc
    ${SRCDIR}/location.cc
    ${SRCDIR}/checkfile.cc
    
)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
add_executable(certctl WIN32 ${SRC})
target_link_libraries(certctl PRIVATE wintrust Crypt32 msi cryptui)
