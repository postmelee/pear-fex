add_library(CommonWindowsRuntime STATIC LoadConfig.S)
add_subdirectory(CRT)
add_subdirectory(WinAPI)

target_link_libraries(CommonWindowsRuntime FEXCore_Base JemallocLibs)
target_compile_options(CommonWindowsRuntime PRIVATE -Wno-inconsistent-dllimport)
target_include_directories(CommonWindowsRuntime PRIVATE "${CMAKE_SOURCE_DIR}/Source/Windows/include/")

add_library(CommonWindows STATIC
  Allocator.cpp
  CPUFeatures.cpp
  DarwinConfigPolicy.cpp
  EnvironmentVariablesHandling.cpp
  FEXUnixLib.cpp
  SHMStats.cpp
  InvalidationTracker.cpp
  ImageTracker.cpp
  Logging.cpp
  PearFEXMemory.cpp
  Threads.cpp)

target_link_libraries(CommonWindows FEXCore_Base)
target_include_directories(CommonWindows PRIVATE "${CMAKE_SOURCE_DIR}/Source/Windows/include/")

# Only the independently materialized authoritative wire header is admitted.
# Do not add the Wine source include tree to the FEX cross compiler.
set(PEAR_FEX_MEMORY_INCLUDE_ROOT "" CACHE PATH "Owned one-header Wine memory ABI include root")
if(NOT IS_ABSOLUTE "${PEAR_FEX_MEMORY_INCLUDE_ROOT}" OR
   IS_SYMLINK "${PEAR_FEX_MEMORY_INCLUDE_ROOT}" OR
   IS_SYMLINK "${PEAR_FEX_MEMORY_INCLUDE_ROOT}/wine" OR
   IS_SYMLINK "${PEAR_FEX_MEMORY_INCLUDE_ROOT}/wine/pear_fex_memory.h")
  message(FATAL_ERROR "Pear memory ABI requires an owned absolute non-symlink include root")
endif()
file(GLOB_RECURSE PEAR_MEMORY_HEADERS LIST_DIRECTORIES false RELATIVE
  "${PEAR_FEX_MEMORY_INCLUDE_ROOT}" "${PEAR_FEX_MEMORY_INCLUDE_ROOT}/*")
if(NOT PEAR_MEMORY_HEADERS STREQUAL "wine/pear_fex_memory.h")
  message(FATAL_ERROR "Pear memory ABI include root must contain exactly one selected header")
endif()
file(SHA256 "${PEAR_FEX_MEMORY_INCLUDE_ROOT}/wine/pear_fex_memory.h" PEAR_MEMORY_HEADER_SHA256)
if(NOT PEAR_MEMORY_HEADER_SHA256 STREQUAL "a089b475fe6d6f2401977319eb4f0702e85c0753063f5748093131088f9f8b55")
  message(FATAL_ERROR "Pear memory ABI header differs from the selected Wine owner source")
endif()
target_include_directories(FEXCore_Base PUBLIC "${PEAR_FEX_MEMORY_INCLUDE_ROOT}")
target_compile_definitions(FEXCore_Base PUBLIC PEAR_FEX_MEMORY_OWNER=1)
