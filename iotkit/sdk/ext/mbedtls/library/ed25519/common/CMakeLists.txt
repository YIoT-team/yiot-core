# Just define ed25519 implementation source files

file(GLOB src_c "*.c")
set(src_ed25519_common "${src_c}" CACHE INTERNAL "")
