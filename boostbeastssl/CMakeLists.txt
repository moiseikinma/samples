cmake_minimum_required(VERSION 3.8.0)
project(boostbeastssl LANGUAGES CXX)
SET(CMAKE_CONFIGURATION_TYPES Release Debug)

set(Boost_USE_STATIC_LIBS     ON)
set(Boost_USE_MULTITHREADED   ON)
set(Boost_USE_STATIC_RUNTIME  ON)
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

add_executable(boostbeastssl main.cpp)
target_link_libraries(boostbeastssl
	OpenSSL::SSL 
	OpenSSL::Crypto
	Boost::boost
	crypt32
)
set_target_properties(boostbeastssl 
	PROPERTIES
		COMPILE_DEFINITIONS "_WIN32_WINNT=0x0601;_UNICODE;UNICODE;WIN32_LEAN_AND_MEAN;NOMINMAX"
		COMPILE_OPTIONS "/MT$<$<CONFIG:Debug>:d>;/std:c++17"
)