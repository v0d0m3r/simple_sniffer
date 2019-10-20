set("${PROJECT}_BINARY_DIR"  bin)
set("${PROJECT}_SOURCE_DIR" src:include)
set("${PROJECT}_LIB_DIR" lib)

set(CMAKE_INCLUDE_PATH ${${PROJECT}_SOURCE_DIR})
set(CMAKE_LIBRARY_PATH ${${PROJECT}_LIB_DIR})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/${${PROJECT}_BINARY_DIR})
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Debug)

set(ERR_NO_UNIX "Cannot build on non Unix systems")

if (WITH_DEBUG_MODE)
     ADD_DEFINITIONS(-DMY_DEBUG_MODE=1)
endif()

if (CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb -std=gnu99 --pedantic")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0 -v -L/usr/local/lib -L/usr/lib")
    #set(CMAKE_C_COMPILER_FLAGS "${CMAKE_C_FLAGS} -O2 -std=gnu99 --pedantic")
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG")
else ()
    message(FATAL_ERROR ${ERR_NO_UNIX})
endif ()
