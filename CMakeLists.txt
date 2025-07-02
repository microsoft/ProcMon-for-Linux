#
#
#    Procmon-for-Linux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    MIT License
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#

#################################################################################
#
# CMakeLists.txt
#
# Build script
#
#################################################################################

#################################################################################
# NOTE:                                                                         #
# Please compile in a build directory rather than the source directory.         #
# From Procmon/linux:                                                            #
#                                                                               #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
# If you later change this CMakeLists.txt file, remake the build directory.     #
#                                                                               #
#    $ cd ..                                                                    #
#    $ rm -rf build                                                             #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
#################################################################################
cmake_minimum_required (VERSION 3.14)

#
# Set the project version number.
#
if (DEFINED ENV{VERSION})
  project (procmon VERSION $ENV{VERSION})
else()
  project (procmon VERSION 0.0.0)
endif()

set(PROJECT_VERSION_TWEAK 0)
file(READ "dist/changelog" CHANGE_LOG)

# Find ncursesw version 6
find_library(NCURSESW6_LIBRARY NAMES ncursesw.so.6 ncursesw PATHS /usr/lib /usr/lib64 /lib /lib64)
find_path(NCURSESW6_INCLUDE_DIR NAMES ncursesw/ncurses.h ncurses.h PATHS /usr/include /usr/local/include)

if(NOT NCURSESW6_LIBRARY)
    message(FATAL_ERROR "libncursesw.so.6 not found. Please install ncursesw version 6.")
endif()
if(NOT NCURSESW6_INCLUDE_DIR)
    message(FATAL_ERROR "ncursesw.h not found. Please install ncurses-devel.")
endif()

find_library(PANELW6_LIBRARY NAMES panelw.so.6 panelw PATHS /usr/lib /usr/lib64 /lib /lib64)
if(NOT PANELW6_LIBRARY)
    message(FATAL_ERROR "libpanelw.so.6 not found. Please install ncursesw version 6.")
endif()

set(LD "/usr/bin/ld")


#
# enable Debug while pre-release; re-enable it post-release to add symbols to binary
#
#set(CMAKE_BUILD_TYPE Debug)
#option(DEBUG_K "Enter debug mode" On)

#
# package name
#
set(PACKAGE_NAME "procmon")

#
# MAN page
#
set(PROCMON_COMPRESS_MAN "procmon.1.gz")

execute_process(
    COMMAND date "+%d %b %Y"
    OUTPUT_VARIABLE BUILD_DATE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

configure_file(
    "${CMAKE_SOURCE_DIR}/procmon_template.1"
    "${PROJECT_BINARY_DIR}/procmon.1"
    @ONLY
)

add_custom_target(procmonManPageCompress ALL
                  DEPENDS ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_MAN}
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_MAN}
                   COMMAND gzip -9n -f -c "${PROJECT_BINARY_DIR}/procmon.1" > ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_MAN}
                   COMMENT "Compressing Procmon man page"
                   DEPENDS "${PROJECT_BINARY_DIR}/procmon.1"
                  )

#
# Change log
#
set(PROCMON_COMPRESS_CHANGELOG "changelog.gz")

add_custom_target(procmonChangelogCompress ALL
                  DEPENDS ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_CHANGELOG}
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_CHANGELOG}
                   COMMAND cp "${CMAKE_SOURCE_DIR}/dist/changelog" ${PROJECT_BINARY_DIR} && gzip -f -c "${CMAKE_SOURCE_DIR}/dist/changelog" > ${PROJECT_BINARY_DIR}/${PROCMON_COMPRESS_CHANGELOG}
                   COMMENT "Compressing changelog"
                   DEPENDS "${CMAKE_SOURCE_DIR}/dist/changelog"
                  )



#
# Configure files
#
configure_file ("${PROJECT_SOURCE_DIR}/src/version.h.in"
                "${PROJECT_BINARY_DIR}/src/version.h"
               )

configure_file(dist/DEBIAN.in/control.in DEBIANcontrol)
configure_file(dist/SPECS.in/spec.in SPECS.spec)

include(FetchContent)

#
# Include Sqlite3 amalgamation.
#
add_library(sqlite3-static STATIC
            "${CMAKE_SOURCE_DIR}/vendor/sqlite3/sqlite3.c"
           )

set_target_properties(sqlite3-static
                      PROPERTIES
                      INTERFACE_LINK_LIBRARIES "dl;pthread"
                     )

#
# Fetch Catch2 testing framework.
#
FetchContent_Declare(Catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG        v2.7.2
                    )
FetchContent_MakeAvailable(Catch2)

#
# Set compiler flags.
#
set (CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -DELPP_THREAD_SAFE")
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED True)

#
# set paths
#
set (PROCMON_TRACER_SRC "${CMAKE_SOURCE_DIR}/src/tracer/ebpf")
set (PROCMON_LOGGING_SRC "${CMAKE_SOURCE_DIR}/src/logging")
set (PROCMON_COMMON_SRC "${CMAKE_SOURCE_DIR}/src/common")
set (PROCMON_STORAGE_SRC "${CMAKE_SOURCE_DIR}/src/storage")
set (PROCMON_CONFIG_SRC "${CMAKE_SOURCE_DIR}/src/configuration")
set (PROCMON_DISPLAY_SRC "${CMAKE_SOURCE_DIR}/src/display")
set (PROCMON_EBPF_SRC "${CMAKE_SOURCE_DIR}/src/tracer/ebpf/kern")
set (PROCMON_SYM_SRC "${CMAKE_SOURCE_DIR}/src/sym")

add_executable(procmon
               src/procmon.cpp
               src/installer.cpp
              "${PROCMON_TRACER_SRC}/ebpf_tracer_engine.cpp"
              "${PROCMON_TRACER_SRC}/syscall_schema.cpp"
              "${PROCMON_LOGGING_SRC}/easylogging++.cc"
              "${PROCMON_COMMON_SRC}/cli_utils.cpp"
              "${PROCMON_COMMON_SRC}/printable.cpp"
              "${PROCMON_STORAGE_SRC}/sqlite3_storage_engine.cpp"
              "${PROCMON_STORAGE_SRC}/storage_proxy.cpp"
              "${PROCMON_STORAGE_SRC}/mock_storage_engine.cpp"
              "${PROCMON_CONFIG_SRC}/procmon_configuration.cpp"
              "${PROCMON_DISPLAY_SRC}/column.cpp"
              "${PROCMON_DISPLAY_SRC}/event_formatter.cpp"
              "${PROCMON_DISPLAY_SRC}/headless.cpp"
              "${PROCMON_DISPLAY_SRC}/kill_event_formatter.cpp"
              "${PROCMON_DISPLAY_SRC}/screen.cpp"
              "${PROCMON_SYM_SRC}/bcc_proc.cpp"
              "${PROCMON_SYM_SRC}/bcc_syms.cc"
              "${PROCMON_SYM_SRC}/bcc_elf.cpp"
              "${PROCMON_SYM_SRC}/bcc_perf_map.cpp"
              "${PROCMON_SYM_SRC}/bcc_zip.cpp"
              procmonEBPFkern4.17-5.1.o.o
              procmonEBPFkern5.2.o.o
              procmonEBPFkern5.3-5.5.o.o
              procmonEBPFkern5.6-.o.o
              procmonEBPFkern4.17-5.1_core.o.o
              procmonEBPFkern5.2_core.o.o
              procmonEBPFkern5.3-5.5_core.o.o
              procmonEBPFkern5.6-_core.o.o
             )

target_include_directories(procmon PUBLIC
                           /opt/sysinternalsEBPF/libbpf
                           #"/usr/include/bpf"
                           "${PROJECT_BINARY_DIR}/src/"
                           "${CMAKE_SOURCE_DIR}/vendor/sqlite3"
                           "/opt/sysinternalsEBPF/ebpfKern"
                           "${PROCMON_SYM_SRC}"
                           ${CURSES_INCLUDE_DIR}
                          )

target_link_libraries(procmon
                      sysinternalsEBPF
                      sqlite3-static
                      ${NCURSESW6_LIBRARY}
                      ${PANELW6_LIBRARY}
                      elf
                      stdc++fs
                     )

set(PACKED_BINARY_FILES
    procmonEBPFkern4.17-5.1.o
    procmonEBPFkern5.2.o
    procmonEBPFkern5.3-5.5.o
    procmonEBPFkern5.6-.o
    procmonEBPFkern4.17-5.1_core.o
    procmonEBPFkern5.2_core.o
    procmonEBPFkern5.3-5.5_core.o
    procmonEBPFkern5.6-_core.o
   )

foreach(BIN_FILE IN LISTS PACKED_BINARY_FILES)
  add_custom_command(OUTPUT "${BIN_FILE}.o"
                    COMMAND "${LD}" -r -b binary -o "${BIN_FILE}.o" "${BIN_FILE}"
                    COMMENT "Packing ${BIN_FILE} into ${BIN_FILE}.o"
                    DEPENDS ${PROJECT_BINARY_DIR}/${BIN_FILE}
                    )
endforeach(BIN_FILE)

#
# Make package(s)
#
add_custom_target(deb
    COMMAND "${CMAKE_SOURCE_DIR}/makePackages.sh" "${CMAKE_SOURCE_DIR}" "${PROJECT_BINARY_DIR}" "${PACKAGE_NAME}" "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}" "0" "deb"
    DEPENDS "${CMAKE_SOURCE_DIR}/dist" "${PROJECT_BINARY_DIR}/procmon"
)

add_custom_target(rpm
    COMMAND "${CMAKE_SOURCE_DIR}/makePackages.sh" "${CMAKE_SOURCE_DIR}" "${PROJECT_BINARY_DIR}" "${PACKAGE_NAME}" "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}" "0" "rpm"
    DEPENDS "${CMAKE_SOURCE_DIR}/dist" "${PROJECT_BINARY_DIR}/procmon"
)

#
# EBPF
#
# This section makes the EBPF programs
#

set(EBPF_DEPENDS
    "${PROCMON_EBPF_SRC}/procmonGenericEntry_rawtp.c"
    "${PROCMON_EBPF_SRC}/procmonGenericExit_rawtp.c"
   )

set(EBPF_PROGS
   procmonEBPFkern4.17-5.1
   procmonEBPFkern5.2
   procmonEBPFkern5.3-5.5
   procmonEBPFkern5.6-
   )


#
# set binaries and options for clang and llc
#
set(CLANG "clang")
set(LLC "llc")
set(CLANG_OPTIONS -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  -g
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  -D __linux__
                  )
if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES
                   -I "${CMAKE_SOURCE_DIR}/gnu"
                   -I "${CMAKE_SOURCE_DIR}"
                   -I "/opt/sysinternalsEBPF/ebpfKern"
                   -I "/opt/sysinternalsEBPF/libbpf"
                   -I "${CMAKE_BINARY_DIR}"
                   )

set(EBPF_CORE_PROG_SUFFIX "_core")

#
# function to make ebpf programs
#
function(build_ebpf ebpfsrc suffix)
    add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/${ebpfsrc}${suffix}.o
                       COMMAND "${CLANG}" -nostdinc ${CLANG_INCLUDES} -isystem "/usr/include" -isystem "/usr/include/x86_64-linux-gnu"  -isystem `gcc -print-file-name=include` ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -target bpf -fno-stack-protector -c "${PROCMON_EBPF_SRC}/${ebpfsrc}.c" -o "${PROJECT_BINARY_DIR}/${ebpfsrc}${suffix}.o"
                       COMMENT "Building EBPF object ${ebpfsrc}${suffix}.o"
                       DEPENDS ${PROCMON_EBPF_SRC}/${ebpfsrc}.c ${EBPF_DEPENDS}
                       )
endfunction()

#
# Loop for all ebpf programs
#
foreach(EBPF_PROG IN LISTS EBPF_PROGS)

    #
    # add custom target to build all ebpf programs with 'all'
    #
    add_custom_target(${EBPF_PROG} ALL
                      DEPENDS "${PROCMON_EBPF_SRC}/${EBPF_PROG}.c"
                      COMMENT "Building EBPF program ${EBPF_PROG}.c"
                     )

    #
    # first build NON CORE program
    #
    list(REMOVE_ITEM CLANG_DEFINES -DEBPF_CO_RE)
    build_ebpf(${EBPF_PROG} "")
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)

    #
    # next build CORE program
    #
    list(APPEND CLANG_DEFINES -DEBPF_CO_RE)
    build_ebpf(${EBPF_PROG} ${EBPF_CORE_PROG_SUFFIX})
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}${EBPF_CORE_PROG_SUFFIX}.o)

endforeach(EBPF_PROG)

# Define the parse_syscalls target
add_executable(getsyscalls getsyscalls/getsyscalls.cpp)

# Add a custom target to run parse_syscalls
add_custom_target(run_getsyscalls
    COMMAND ${CMAKE_SOURCE_DIR}/getsyscalls/getsyscalls.sh 6.7
    DEPENDS getsyscalls
    COMMENT "Running getsyscalls"
)

# Add dependencies to ensure parse_syscalls runs before other targets
add_dependencies(procmon run_getsyscalls)
