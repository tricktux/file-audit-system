include(ExternalProject)

# build directory
set(libconfig_PREFIX ${CMAKE_BINARY_DIR}/external/libconfig-prefix)
# install directory
set(libconfig_INSTALL ${CMAKE_BINARY_DIR}/external/libconfig-install)

ExternalProject_Add(
	libconfig
	PREFIX ${libnvc_PREFIX}
	GIT_REPOSITORY https://github.com/hyperrealm/libconfig
	GIT_TAG				 v1.7.2
	GIT_SHALLOW		 1
	GIT_PROGRESS	 1
	CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
	-DCMAKE_INSTALL_PREFIX=${libconfig_INSTALL}
	-DBUILD_EXAMPLES=OFF
	-DBUILD_SHARED_LIBS=OFF
	-DBUILD_TESTS=OFF

	LOG_DOWNLOAD 1
	LOG_INSTALL 1
	)

set(LIBCONFIG_FOUND TRUE)
set(LIBCONFIG_INCLUDE_DIRS ${libconfig_INSTALL}/include)
set(LIBCONFIG_LIBRARIES ${libconfig_INSTALL}/lib/libconfig++.a)
set(LIBCONFIG_LIBRARY_DIRS ${libconfig_INSTALL}/lib)
set(LIBCONFIG_EXTERNAL TRUE)
