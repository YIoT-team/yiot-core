#  ────────────────────────────────────────────────────────────
#                     ╔╗  ╔╗ ╔══╗      ╔════╗
#                     ║╚╗╔╝║ ╚╣╠╝      ║╔╗╔╗║
#                     ╚╗╚╝╔╝  ║║  ╔══╗ ╚╝║║╚╝
#                      ╚╗╔╝   ║║  ║╔╗║   ║║
#                       ║║   ╔╣╠╗ ║╚╝║   ║║
#                       ╚╝   ╚══╝ ╚══╝   ╚╝
#    ╔╗╔═╗                    ╔╗                     ╔╗
#    ║║║╔╝                   ╔╝╚╗                    ║║
#    ║╚╝╝  ╔══╗ ╔══╗ ╔══╗  ╔╗╚╗╔╝  ╔══╗ ╔╗ ╔╗╔╗ ╔══╗ ║║  ╔══╗
#    ║╔╗║  ║║═╣ ║║═╣ ║╔╗║  ╠╣ ║║   ║ ═╣ ╠╣ ║╚╝║ ║╔╗║ ║║  ║║═╣
#    ║║║╚╗ ║║═╣ ║║═╣ ║╚╝║  ║║ ║╚╗  ╠═ ║ ║║ ║║║║ ║╚╝║ ║╚╗ ║║═╣
#    ╚╝╚═╝ ╚══╝ ╚══╝ ║╔═╝  ╚╝ ╚═╝  ╚══╝ ╚╝ ╚╩╩╝ ║╔═╝ ╚═╝ ╚══╝
#                    ║║                         ║║
#                    ╚╝                         ╚╝
#
#    Lead Maintainer: Roman Kutashenko <kutashenko@gmail.com>
#  ────────────────────────────────────────────────────────────


# ---------------------------------------------------------------------------
#   Include once.
# ---------------------------------------------------------------------------
include_guard()

# ---------------------------------------------------------------------------
#   Helpers.
# ---------------------------------------------------------------------------
include(TransitiveToolchainArgs)

# ---------------------------------------------------------------------------
#   Known OpenWRT toolchain configuration arguments.
# ---------------------------------------------------------------------------
function(TRANSITIVE_OPENWRT_ARGS_ADD)
        transitive_args_add(
                CMAKE_SYSTEM_NAME
                CMAKE_SYSTEM_VERSION
                CMAKE_SYSTEM_PROCESSOR
                CMAKE_BUILD_TYPE
                CMAKE_C_FLAGS_RELEASE 
                CMAKE_CXX_FLAGS_RELEASE
                CMAKE_C_COMPILER
                CMAKE_C_COMPILER_ARG1 
                CMAKE_CXX_COMPILER
                CMAKE_CXX_COMPILER_ARG1
                CMAKE_ASM_COMPILER
                CMAKE_ASM_COMPILER_ARG1 
                CMAKE_EXE_LINKER_FLAGS
                CMAKE_MODULE_LINKER_FLAGS
                CMAKE_SHARED_LINKER_FLAGS
                CMAKE_AR
                CMAKE_NM
                CMAKE_RANLIB
                CMAKE_FIND_ROOT_PATH
                CMAKE_FIND_ROOT_PATH_MODE_PROGRAM 
                CMAKE_FIND_ROOT_PATH_MODE_LIBRARY 
                CMAKE_FIND_ROOT_PATH_MODE_INCLUDE 
                CMAKE_STRIP 
                CMAKE_INSTALL_PREFIX
                DL_LIBRARY
                CMAKE_PREFIX_PATH
                CMAKE_SKIP_RPATH 
                ENABLE_TESTING
                ENABLE_HEAVY_TESTS 
                CMAKE_CXX_COMPILER_FORCED)
endfunction()

# ---------------------------------------------------------------------------
#   Entrypoint
# ---------------------------------------------------------------------------
transitive_openwrt_args_add()