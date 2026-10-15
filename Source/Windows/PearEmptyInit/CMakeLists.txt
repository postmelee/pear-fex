# Private original finite target. The proof header stays closed even when a
# root-reviewed constructor explicitly selects this compile-only target.
if(NOT ARCHITECTURE_arm64 OR ARCHITECTURE_arm64ec OR NOT ENABLE_FEX_ALLOCATOR)
  message(FATAL_ERROR "Pear empty fixture requires the selected ordinary ARM64 allocator target")
endif()
add_library(pearemptyinit SHARED Fixture.cpp CheckedCRT.cpp Fixture.def $<TARGET_OBJECTS:FEXCore_object>)
patch_library_wine(pearemptyinit)
target_include_directories(pearemptyinit PRIVATE
  "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
  "${CMAKE_SOURCE_DIR}/Source/Windows/"
  "${CMAKE_SOURCE_DIR}/Source/Tools/"
  "${CMAKE_SOURCE_DIR}/Source/")
target_link_libraries(pearemptyinit PRIVATE FEXCore_Base Common CommonTools CommonWindows CommonWindowsRuntime ntdll_ex)
target_link_options(pearemptyinit PRIVATE -static -nostdlib -nostartfiles -nodefaultlibs -lc++abi -lc++ -lunwind)
target_link_libraries(pearemptyinit PRIVATE ${LIBGCC_PATH})
install(TARGETS pearemptyinit RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime)
