cmake_minimum_required(VERSION 3.31)
project(grg_k)

set(CMAKE_CXX_STANDARD 20)

add_executable(grg_k main.cpp gost/gost.cpp gost/gost.hpp morse/morse.cpp morse/morse.h rot13/rot13_bitwise.h rot13/rot13_bitwise.cpp)
