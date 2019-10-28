include(ExternalProject)

# build directory
set(iniparser_PREFIX ${CMAKE_BINARY_DIR}/external/iniparser-prefix)
# install directory
set(iniparser_INSTALL ${CMAKE_BINARY_DIR}/external/iniparser-install)

ExternalProject_Add(
	iniparser
	PREFIX ${iniparser_PREFIX}
	GIT_REPOSITORY https://github.com/ndevilla/iniparser
	GIT_TAG				 v4.1
	GIT_SHALLOW		 1
	GIT_PROGRESS	 1
	BUILD_IN_SOURCE 1
	CONFIGURE_COMMAND ""
	BUILD_COMMAND make
	INSTALL_COMMAND ""
	)


ExternalProject_Get_property(iniparser SOURCE_DIR)
set(INIPARSER_FOUND TRUE)
set(INIPARSER_INCLUDE_DIRS ${SOURCE_DIR}/src)
set(INIPARSER_LIBRARIES ${SOURCE_DIR}/libiniparser.a)
set(INIPARSER_LIBRARY_DIRS ${SOURCE_DIR})
set(INIPARSER_EXTERNAL TRUE)
