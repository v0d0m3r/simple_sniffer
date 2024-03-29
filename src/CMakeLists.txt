set("${PROJECT}_VERSION_MAJ" 0)
set("${PROJECT}_VERSION_MIN" 1)
set("${PROJECT}_VERSION_A" 1)
set("${PROJECT}_VERSION_B" 1)
set("${PROJECT}_VERSION" ${${PROJECT}_VERSION_MAJ}0${${PROJECT}_VERSION_MIN}0${${PROJECT}_VERSION_A}0${${PROJECT}_VERSION_B})

message(STATUS ${${PROJECT}_VERSION})

# основной файл программы
set(MAIN_SOURCES
    simple_sniffer.c
)

# непубличные пары исходников
set(PRIVATE_CLASSES
    "Settings"
    "Snif_lib"
)

# файлы только заголовочные, у которых нет пары-исходника
set(HEADERS_ONLY
    ""
    ""
)

# публичные исходники
set(PUBLIC_CLASSES)

# используемые в программе библиотеки
set(ADDITIONAL_LIBRARIES
    "pcap"
    "json-c"
    #    pthread
)

set(PUBLIC_HEADERS)
set(SOURCES)

foreach (class ${PRIVATE_CLASSES})
    LIST (APPEND SOURCES ${class}.c)
    LIST (APPEND HEADERS ${class}.h)
endforeach ()

foreach (class ${HEADERS_ONLY})
    LIST (APPEND HEADERS ${class}.h)
endforeach ()

foreach (class ${PUBLIC_CLASSES})
    LIST (APPEND SOURCES ${class}.c)
    LIST (APPEND HEADERS ../include/${PROJECT}/${class}.h)
    LIST (APPEND PUBLIC_HEADERS ../include/${PROJECT}/${class}.h)
endforeach ()

add_executable(${PROJECT} ${MAIN_SOURCES} ${SOURCES})

target_link_libraries(${PROJECT} ${ADDITIONAL_LIBRARIES})

set_target_properties(${PROJECT} PROPERTIES VERSION "${${PROJECT}_VERSION}" SOVERSION "0")

INSTALL(
    TARGETS
    ${PROJECT}
    DESTINATION
    lib${LIB_SUFFIX}
)

INSTALL(
    FILES
    ${PUBLIC_HEADERS}
    DESTINATION
    include/${PROJECT}
)
