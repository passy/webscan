CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(webscan C)

# Where to find local cmake scripts
SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

ADD_DEFINITIONS(-ggdb -fsigned-char -Wall -W -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Winline -Werror)
ADD_SUBDIRECTORY(client bin)
