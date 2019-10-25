# All the source files for the bot.
file(GLOB SOURCES "*.cpp")

include_directories(${CMAKE_SOURCE_DIR}/inc)

# Set ExecutableName.
add_executable(file-audit ${SOURCES})

