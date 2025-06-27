# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Simple finder for GMP library

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_GMP QUIET gmp)
endif()

find_path(GMP_INCLUDE_DIR
  NAMES gmp.h
  PATHS ${PC_GMP_INCLUDE_DIRS}
)

find_library(GMP_LIBRARY_RELEASE
  NAMES gmp
  PATHS ${PC_GMP_LIBRARY_DIRS}
)
find_library(GMP_LIBRARY_DEBUG
  NAMES gmpd gmp
  PATHS ${PC_GMP_LIBRARY_DIRS}
)

include(SelectLibraryConfigurations)
select_library_configurations(GMP)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP
  REQUIRED_VARS GMP_LIBRARY GMP_INCLUDE_DIR
  VERSION_VAR PC_GMP_VERSION
)

if(GMP_FOUND AND NOT TARGET GMP::GMP)
  add_library(GMP::GMP UNKNOWN IMPORTED)
  if(GMP_LIBRARY_RELEASE)
    set_property(TARGET GMP::GMP APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
    set_target_properties(GMP::GMP PROPERTIES IMPORTED_LOCATION_RELEASE "${GMP_LIBRARY_RELEASE}")
  endif()
  if(GMP_LIBRARY_DEBUG)
    set_property(TARGET GMP::GMP APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
    set_target_properties(GMP::GMP PROPERTIES IMPORTED_LOCATION_DEBUG "${GMP_LIBRARY_DEBUG}")
  endif()
  set_target_properties(GMP::GMP PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}")
endif()

mark_as_advanced(GMP_INCLUDE_DIR)
