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

# Download dependencies
file(GLOB EXTERNAL_SUBDIR
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/external/*.cmake")

foreach (DEPS ${EXTERNAL_SUBDIR})
	include(${DEPS})
endforeach ()

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

# Set sanitizers
if (EXISTS "${CMAKE_SOURCE_DIR}/cmake/sanitizers")
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
		"${CMAKE_SOURCE_DIR}/cmake/sanitizers")
	set (SANITIZERS_FOUND ON)
endif ()

# Depends on clang and llvm being installed
# cmake -DSANITIZE_ADDRESS=ON ..
# ./bin/<executable_name>
if (SANITIZERS_FOUND)
	option(SANITIZE_ADDRESS "Enable Address Sanitizer" OFF)
	option(SANITIZE_MEMORY "Enable Memory Sanitizer" OFF)
	option(SANITIZE_THREAD "Enable Thread Sanitizer" OFF)
	option(SANITIZE_UNDEFINED "Enable Undefined Behavior Sanitizer" OFF)
endif ()

# add flags to release mode
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS}")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-strict-aliasing")
SET(CMAKE_CXX_FLAGS_RELEASE
	"${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wfatal-errors -Wextra -Wunused -Werror")

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

if (SANITIZERS_FOUND)
	find_package(Sanitizers REQUIRED)
endif ()

add_subdirectory("src")

option(ENABLE_TESTS "Build tests" OFF)
if(ENABLE_TESTS)
	enable_testing()
	add_subdirectory("tests")
endif()

include (GNUInstallDirs)
install (TARGETS file-monitor)
install (FILES ${CMAKE_SOURCE_DIR}/config/file-monitor.conf
					DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
	)
