# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Simple finder for Crypto++ library

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_CryptoPP QUIET libcrypto++ cryptopp)
endif()

find_path(CryptoPP_INCLUDE_DIR
  NAMES cryptopp/config.h
  PATHS ${PC_CryptoPP_INCLUDE_DIRS}
)

find_library(CryptoPP_LIBRARY_RELEASE
  NAMES cryptopp
  PATHS ${PC_CryptoPP_LIBRARY_DIRS}
)
find_library(CryptoPP_LIBRARY_DEBUG
  NAMES cryptoppd cryptopp
  PATHS ${PC_CryptoPP_LIBRARY_DIRS}
)

include(SelectLibraryConfigurations)
select_library_configurations(CryptoPP)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CryptoPP
  REQUIRED_VARS CryptoPP_LIBRARY CryptoPP_INCLUDE_DIR
  VERSION_VAR PC_CryptoPP_VERSION
)

if(CryptoPP_FOUND AND NOT TARGET CryptoPP::CryptoPP)
  add_library(CryptoPP::CryptoPP UNKNOWN IMPORTED)
  if(CryptoPP_LIBRARY_RELEASE)
    set_property(TARGET CryptoPP::CryptoPP APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
    set_target_properties(CryptoPP::CryptoPP PROPERTIES IMPORTED_LOCATION_RELEASE "${CryptoPP_LIBRARY_RELEASE}")
  endif()
  if(CryptoPP_LIBRARY_DEBUG)
    set_property(TARGET CryptoPP::CryptoPP APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
    set_target_properties(CryptoPP::CryptoPP PROPERTIES IMPORTED_LOCATION_DEBUG "${CryptoPP_LIBRARY_DEBUG}")
  endif()
  set_target_properties(CryptoPP::CryptoPP PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CryptoPP_INCLUDE_DIR}")
endif()

mark_as_advanced(CryptoPP_INCLUDE_DIR)
