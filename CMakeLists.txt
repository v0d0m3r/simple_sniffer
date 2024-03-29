cmake_minimum_required(VERSION 2.6)

cmake_policy(SET CMP0011 NEW)
cmake_policy(SET CMP0003 OLD)

OPTION(WITH_DEBUG_MODE "Build with debug mode" ON)

if (NOT UNIX)
    message(FATAL_ERROR "Not Unix!")
endif ()

set(PROJECT simple_sniffer)
set(LIBRARIES)

project(${PROJECT})
include(${PROJECT}.cmake)

foreach (LIBRARY ${LIBRARIES})
    find_library("${LIBRARY}_FOUND" ${LIBRARY})
    message(STATUS "Check the ${LIBRARY} is installed: " ${${LIBRARY}_FOUND})
    if ("${${LIBRARY}_FOUND}" STREQUAL "${LIBRARY}_FOUND-NOTFOUND")
        message(STATUS "Adding library sources")
        add_subdirectory(../${LIBRARY} lib/${LIBRARY})
    endif ()
endforeach ()

set(TARGETS "")
set(HEADERS "")

message(STATUS "SOURCES: ${SOURCES}")
add_subdirectory(src)
