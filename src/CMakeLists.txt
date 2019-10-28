# All the source files for the bot.
file(GLOB SOURCES
	"${CMAKE_SOURCE_DIR}/src/main.cpp"
	"${CMAKE_SOURCE_DIR}/src/monitor.cpp"
	)

include_directories(${CMAKE_SOURCE_DIR}/inc)
if (INIPARSER_FOUND)
	include_directories(${INIPARSER_INCLUDE_DIRS})
endif ()

# Set ExecutableName.
add_executable(file-monitor ${SOURCES})

target_link_libraries(file-monitor audit)
target_link_libraries(file-monitor pthread)
if (INIPARSER_FOUND)
	target_link_libraries(file-monitor ${INIPARSER_LIBRARIES})
endif ()

