FIND_PACKAGE(PCAP REQUIRED)
FIND_PACKAGE(CAP REQUIRED)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR}
   ${CMAKE_CURRENT_SOURCE_DIR})

ADD_EXECUTABLE(webscan request.c analyze.c webscan.c main.c)
TARGET_LINK_LIBRARIES(webscan pcap)
TARGET_LINK_LIBRARIES(webscan cap)
