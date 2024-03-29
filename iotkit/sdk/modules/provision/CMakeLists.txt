#   Copyright (C) 2015-2019 Virgil Security Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(vs-module-provision VERSION 0.1.0 LANGUAGES C)

#
#   Check required CMake variables
#
if(NOT VIRGIL_IOT_DIRECTORY)
    message(FATAL_ERROR "[vs-module-provision] VIRGIL_IOT_DIRECTORY variable containing path to the Virgil IOT SDK source is not specified")
endif()

#
#   Add TrustList library
#
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/trust_list)

#
#   Provision library
#
add_library(vs-module-provision
        src/provision.c
        src/license.c
        )

target_sources(vs-module-provision
        PRIVATE
        # Headers
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/provision/provision.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/provision/provision-structs.h
        ${CMAKE_CURRENT_LIST_DIR}/include/virgil/iot/provision/license.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/provision.c
        ${CMAKE_CURRENT_LIST_DIR}/src/license.c
        )

#
#   Set additional compiler flags
#

if ("${CFLAGS_PLATFORM}" STREQUAL "")
    message("-- No CFLAGS_PLATFORM")
else()
    message("-- CFLAGS_PLATFORM = ${CFLAGS_PLATFORM}")
    string(REPLACE " " ";" CFLAGS_PLATFORM ${CFLAGS_PLATFORM})
endif()

#
#   Compile definitions
#

target_compile_options(vs-module-provision
        PRIVATE -Wall -Werror ${CFLAGS_PLATFORM})

#
#   Config path
#

target_compile_definitions(vs-module-provision
        PRIVATE "VIRGIL_IOT_MCU_BUILD=$<BOOL:${VIRGIL_IOT_MCU_BUILD}>"
        )

#
#   Common include directories
#
target_include_directories(vs-module-provision
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<BUILD_INTERFACE:${VIRGIL_IOT_SDK_HAL_INC_PATH}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>

        PRIVATE
        $<BUILD_INTERFACE:${VIRGIL_IOT_CONFIG_DIRECTORY}>
        $<BUILD_INTERFACE:${VIRGIL_IOT_DIRECTORY}/modules/protocols/snap/include>
        )

target_link_libraries(vs-module-provision
        PUBLIC
        storage_hal
        trust_list
        vs-module-crypto-high-level
        PRIVATE
        virgil-iot-status-code
        vs-json
        vs-base64
        )

install(TARGETS vs-module-provision
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/virgil
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

if(COMMAND add_clangformat)
#    add_clangformat(vs-module-provision)
endif()