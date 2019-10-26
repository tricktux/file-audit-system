# File:           CMakeLists.txt
# Description:     Code Description
# Author:		    Reinaldo Molina
# Email:          rmolin88 at gmail dot com
# Revision:	    0.0.0
# Created:        Tue Mar 05 2019 06:13
# Last Modified:  Tue Mar 05 2019 06:13

cmake_minimum_required(VERSION 3.1)

# Set ProjectName
project(file-system-audit)

# Set a default build type if none was specified
set(default_build_type "Release")
if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
	set(default_build_type "Debug")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
		STRING "Choose the type of build." FORCE)
	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

OPTION(ENABLE_ASAN "Enable ASAN" OFF)
OPTION(ENABLE_USAN "Enable USAN" OFF)
OPTION(ENABLE_TSAN "Enable TSAN" OFF)

IF(ENABLE_ASAN)
	MESSAGE(STATUS "ASAN enabled")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
ENDIF()

IF(ENABLE_USAN)
	MESSAGE(STATUS "USAN enabled")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined")
ENDIF()

IF(ENABLE_TSAN)
	MESSAGE(STATUS "TSAN enabled")
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=thread")
ENDIF()

# add flags to release mode
# by default won't use release mode
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS}")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-strict-aliasing")
SET(CMAKE_CXX_FLAGS_RELEASE
	"${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wfatal-errors -Wextra -Wunused -Werror")

# always compile libnvc in debug mode
# for trace message use LIBNVC_DEBUG_ARG_LIST to enable
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS}")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")

SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb3 -pedantic")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-strict-aliasing")
SET(CMAKE_CXX_FLAGS_DEBUG
	"${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wextra -Wunused -Werror")

# Specify output directories.
set(EXECUTABLE_OUTPUT_PATH "${PROJECT_BINARY_DIR}/bin")

# Include custom macros to find Glog.
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory("src")

option(ENABLE_TESTS "Build tests" OFF)
if(ENABLE_TESTS)
	enable_testing()
	add_subdirectory("tests")
endif()

install (TARGETS file-monitor)
