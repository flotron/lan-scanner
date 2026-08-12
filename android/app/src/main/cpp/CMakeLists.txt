cmake_minimum_required(VERSION 3.22.1)
project(lanscanner_arp)

add_library(lanscanner_arp SHARED native_arp.cpp)
find_library(log-lib log)
target_link_libraries(lanscanner_arp ${log-lib})
