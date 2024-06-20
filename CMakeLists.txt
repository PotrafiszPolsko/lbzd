cmake_minimum_required(VERSION 3.8.2)
project(BC)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(sodium)
find_package(Boost CONFIG)
find_package(Boost 1.70.0 REQUIRED COMPONENTS log program_options serialization)
find_package(Threads)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug")
endif()

include_directories(SYSTEM ${SODIUM_INCLUDE_DIR})

if (NOT sodium_INCLUDE_DIR AND NOT sodium_LIBRARY_RELEASE)
	set(sodium_INCLUDE_DIR "${SODIUM_INCLUDE_DIR}")
	set(sodium_LIBRARY_RELEASE "${SODIUM_LIBRARY}")
endif()

set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory("${PROJECT_SOURCE_DIR}/leveldb" EXCLUDE_FROM_ALL)
include_directories(SYSTEM "${PROJECT_SOURCE_DIR}/leveldb/include")

set(protobuf_BUILD_TESTS OFF CACHE BOOL "")
add_subdirectory("${PROJECT_SOURCE_DIR}/protobuf/cmake" EXCLUDE_FROM_ALL)

add_custom_target(generate-proto
                    COMMAND protobuf::protoc p2p.proto -I "${PROJECT_SOURCE_DIR}/proto" --cpp_out="${PROJECT_SOURCE_DIR}/src"
                    COMMAND protobuf::protoc blockchain.proto -I "${PROJECT_SOURCE_DIR}/proto" --cpp_out="${PROJECT_SOURCE_DIR}/src")
add_subdirectory("${PROJECT_SOURCE_DIR}/json" EXCLUDE_FROM_ALL)
include_directories(SYSTEM "${PROJECT_SOURCE_DIR}/json/single_include")

add_subdirectory("${PROJECT_SOURCE_DIR}/miniupnp/miniupnpc" EXCLUDE_FROM_ALL)
include_directories(SYSTEM "${PROJECT_SOURCE_DIR}/miniupnp/miniupnpc/include/")

# manual build natpmp library
# I need to do this because on mingw natpmp target must link to "iphlpapi" instead "Iphlpapi"
option(NATPMP "NATPMP default is ON" ON)
if(NATPMP)
    add_definitions(-DNATPMP)
    set (NATPMP_SOURCES
	"${PROJECT_SOURCE_DIR}/libnatpmp/natpmp.c"
	"${PROJECT_SOURCE_DIR}/libnatpmp/getgateway.c"
	)
    if (WIN32)
	set (NATPMP_SOURCES ${NATPMP_SOURCES} "${PROJECT_SOURCE_DIR}/libnatpmp/wingettimeofday.c")
    endif (WIN32)

    # Library itself
    add_library(natpmp STATIC ${NATPMP_SOURCES})
    include_directories(SYSTEM "${PROJECT_SOURCE_DIR}/libnatpmp")
    target_compile_definitions(natpmp PRIVATE -DENABLE_STRNATPMPERR)

    if (WIN32)
	target_link_libraries(natpmp PUBLIC ws2_32 iphlpapi)
	target_compile_definitions(natpmp PUBLIC -DNATPMP_STATICLIB)
    endif (WIN32)
endif (NATPMP)

set(SOURCE_FILES_COMMON
    "${PROJECT_SOURCE_DIR}/miniupnp/miniupnpc/include/"
    "${PROJECT_SOURCE_DIR}/src/mempool.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain.cpp"
    "${PROJECT_SOURCE_DIR}/src/utxo.cpp"
    "${PROJECT_SOURCE_DIR}/src/transaction.cpp"
    "${PROJECT_SOURCE_DIR}/src/txid_generate.cpp"
    "${PROJECT_SOURCE_DIR}/src/merkle_tree.cpp"
    "${PROJECT_SOURCE_DIR}/src/block_verifier.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain_utils.cpp"
    "${PROJECT_SOURCE_DIR}/src/serialization_utils.cpp"
    "${PROJECT_SOURCE_DIR}/src/block.cpp"
    "${PROJECT_SOURCE_DIR}/src/types.cpp"
    "${PROJECT_SOURCE_DIR}/src/log.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain.pb.cc"
    "${PROJECT_SOURCE_DIR}/src/p2p.pb.cc"
    "${PROJECT_SOURCE_DIR}/src/key_manager_bip32.cpp"
    "${PROJECT_SOURCE_DIR}/src/ed25519/add_scalar.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/fe.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/ge.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/key_exchange.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/keypair.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/sc.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/seed.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/sha512.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/sign.c"
    "${PROJECT_SOURCE_DIR}/src/ed25519/verify.c"
    "${PROJECT_SOURCE_DIR}/src/interrupted_sleep.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain_module_builder.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain_module.cpp"
    "${PROJECT_SOURCE_DIR}/src/component.cpp"
    "${PROJECT_SOURCE_DIR}/src/utils.cpp"
    "${PROJECT_SOURCE_DIR}/src/utils_json.cpp"
    "${PROJECT_SOURCE_DIR}/src/blockchain_params.cpp"
    "${PROJECT_SOURCE_DIR}/src/rpc_exec.cpp"
    "${PROJECT_SOURCE_DIR}/src/rpc_module.cpp"
    "${PROJECT_SOURCE_DIR}/src/rpc_server.cpp"
    "${PROJECT_SOURCE_DIR}/src/peer_reference.cpp"
    "${PROJECT_SOURCE_DIR}/src/dh.cpp"
    "${PROJECT_SOURCE_DIR}/src/crypto.cpp"
    "${PROJECT_SOURCE_DIR}/src/port_forwarder.cpp"
    "${PROJECT_SOURCE_DIR}/src/p2p_module.cpp"
    "${PROJECT_SOURCE_DIR}/src/p2p_session_manager.cpp"
    "${PROJECT_SOURCE_DIR}/src/p2p_session_manager_tor.cpp"
    "${PROJECT_SOURCE_DIR}/src/main_module.cpp"
    "${PROJECT_SOURCE_DIR}/src/peer_finder.cpp"
    "${PROJECT_SOURCE_DIR}/src/session.cpp"
    "${PROJECT_SOURCE_DIR}/src/tor_control.cpp"
    "${PROJECT_SOURCE_DIR}/src/tor_socks5_provider.cpp"
    "${PROJECT_SOURCE_DIR}/src/utils-node.cpp"
    "${PROJECT_SOURCE_DIR}/src/main_module_builder.cpp"
    "${PROJECT_SOURCE_DIR}/src/rpc_module_builder.cpp"
    "${PROJECT_SOURCE_DIR}/src/p2p_module_builder.cpp"
    "${PROJECT_SOURCE_DIR}/src/p2p_session_manager_tcp.cpp"
    "${PROJECT_SOURCE_DIR}/src/block_record.cpp"
    "${PROJECT_SOURCE_DIR}/src/authorization_level_data.cpp"
    )

set (SOURCE_FILES_NODE
    "${PROJECT_SOURCE_DIR}/src/tor_socks5_credentials.cpp"
    )

set(TESTS
    "${PROJECT_SOURCE_DIR}/tests/main.cpp"
    "${PROJECT_SOURCE_DIR}/tests/transaction.cpp"
    "${PROJECT_SOURCE_DIR}/tests/blockchain_module.cpp"
    "${PROJECT_SOURCE_DIR}/tests/serialization.cpp"
    "${PROJECT_SOURCE_DIR}/tests/crypto.cpp"
    "${PROJECT_SOURCE_DIR}/tests/rpc.cpp"
    "${PROJECT_SOURCE_DIR}/tests/peer_reference.cpp"
    "${PROJECT_SOURCE_DIR}/tests/main_module.cpp"
    "${PROJECT_SOURCE_DIR}/tests/main_module_mock_builder.cpp"
    "${PROJECT_SOURCE_DIR}/tests/blockchain_module_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/p2p_module_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/utxo_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/blockchain_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/mempool_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/interrupted_sleep.cpp"
    "${PROJECT_SOURCE_DIR}/tests/p2p_module.cpp"
    "${PROJECT_SOURCE_DIR}/tests/p2p_session_manager_tcp_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/p2p_session_manager_tor_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/port_forwarder_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/peer_finder_mock.cpp"
    "${PROJECT_SOURCE_DIR}/tests/p2p_module_builder_tests.cpp"
    )

set_property(SOURCE ${SOURCE_FILES_COMMON} PROPERTY COMPILE_FLAGS "-Wall -Wextra -pedantic -Wno-error")
set_property(SOURCE ${SOURCE_FILES_NODE} PROPERTY COMPILE_FLAGS "-Wall -Wextra -pedantic -Wno-error")
set_property(SOURCE ${TESTS} PROPERTY COMPILE_FLAGS "-Wall -Wextra -pedantic -Wno-error")

if(NOT ANDROID)
        add_definitions(-DBOOST_LOG_DYN_LINK)
endif()

if(MINGW)
	set(WINDOWS_LIBS wsock32 ws2_32 mswsock)
	set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fstack-protector)
endif()

add_library(common_files OBJECT ${SOURCE_FILES_COMMON})
target_include_directories(common_files PUBLIC ${sodium_INCLUDE_DIR} ${BOOST_INCLUDE_DIRS})
target_link_libraries(common_files gtest gmock ${Boost_LIBRARIES} protobuf::libprotoc libminiupnpc-static natpmp)

if((NOT ANDROID) AND (NOT APPLE))
    set(FILESYSTEM_STD_LIB "stdc++fs")
endif()

add_executable(node "${PROJECT_SOURCE_DIR}/src/main-node.cpp" ${SOURCE_FILES_NODE} $<TARGET_OBJECTS:common_files>)
target_include_directories(node PUBLIC ${sodium_INCLUDE_DIR} ${BOOST_INCLUDE_DIRS}
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googletest/include"
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googlemock/include")
target_link_libraries(node PUBLIC gtest gmock ${sodium_LIBRARY_RELEASE} ${Boost_LIBRARIES} leveldb libminiupnpc-static protobuf::libprotoc ${FILESYSTEM_STD_LIB} ${WINDOWS_LIBS} Threads::Threads)
if(NATPMP)
    target_link_libraries(node PUBLIC natpmp)
endif(NATPMP)

if (NOT TARGET gtest)
	add_subdirectory(${PROJECT_SOURCE_DIR}/googletest EXCLUDE_FROM_ALL)
endif()

add_executable(bc-tests EXCLUDE_FROM_ALL ${TESTS} ${SOURCE_FILES_COMMON})
target_compile_options(bc-tests PRIVATE ${WARN_FLAGS})
target_include_directories(bc-tests
			SYSTEM
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googletest/include"
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googlemock/include"
			PRIVATE "${sodium_INCLUDE_DIR}")
target_link_libraries(bc-tests PUBLIC gtest gmock ${sodium_LIBRARY_RELEASE} ${Boost_LIBRARIES} leveldb libminiupnpc-static protobuf::libprotoc ${FILESYSTEM_STD_LIB})
if(NATPMP)
    target_link_libraries(bc-tests PUBLIC natpmp)
endif(NATPMP)
target_compile_definitions(bc-tests PRIVATE -DIVOTING_TESTS)

add_executable(bc-tests-coverage EXCLUDE_FROM_ALL ${TESTS} ${SOURCE_FILES_COMMON})
target_compile_options(bc-tests-coverage PRIVATE ${WARN_FLAGS})
target_include_directories(bc-tests-coverage
			SYSTEM
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googletest/include"
			PRIVATE "${PROJECT_SOURCE_DIR}/googletest/googlemock/include"
			PRIVATE "${sodium_INCLUDE_DIR}")
target_link_libraries(bc-tests-coverage PUBLIC gtest gmock ${sodium_LIBRARY_RELEASE} ${Boost_LIBRARIES} leveldb libminiupnpc-static protobuf::libprotoc ${FILESYSTEM_STD_LIB})
if(NATPMP)
    target_link_libraries(bc-tests-coverage PUBLIC natpmp)
endif(NATPMP)
target_compile_definitions(bc-tests-coverage PRIVATE -DCOVERAGE_TESTS)

# coverage
find_program(LCOV lcov)
if(LCOV)
        if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND ${CMAKE_CXX_COMPILER_ID} MATCHES GNU)
	        include(CodeCoverage)
		set(COVERAGE_LCOV_EXCLUDES '/usr/*'
		    'boost/*'
		    "${PROJECT_SOURCE_DIR}/tests/*"
		    "${PROJECT_SOURCE_DIR}/leveldb/include/leveldb/*"
		    "${PROJECT_SOURCE_DIR}/src/ed25519/*"
		    "${PROJECT_SOURCE_DIR}/protobuf/src/google/protobuf/*"
		    "${PROJECT_SOURCE_DIR}/protobuf/src/google/protobuf/io/*"
		    "${PROJECT_SOURCE_DIR}/protobuf/src/google/protobuf/stubs/*"
		    "${PROJECT_SOURCE_DIR}/googletest/googlemock/include/gmock/*"
		    "${PROJECT_SOURCE_DIR}/googletest/googlemock/include/gmock/internal/*"
		    "${PROJECT_SOURCE_DIR}/googletest/googletest/include/gtest/*"
		    "${PROJECT_SOURCE_DIR}/googletest/googletest/include/gtest/internal/*"
		    "${PROJECT_SOURCE_DIR}/json/single_include/nlohmann/*"
		    "${PROJECT_SOURCE_DIR}/libnatpmp/getgateway.c"
		    "${PROJECT_SOURCE_DIR}/libnatpmp/natpmp.c"
		    "${PROJECT_SOURCE_DIR}/src/blockchain.pb.cc"
		    "${PROJECT_SOURCE_DIR}/src/blockchain.pb.h"
		    "${PROJECT_SOURCE_DIR}/src/p2p.pb.cc"
		    "${PROJECT_SOURCE_DIR}/src/p2p.pb.h"
		)
		APPEND_COVERAGE_COMPILER_FLAGS()
		SETUP_TARGET_FOR_COVERAGE_LCOV(
		    NAME bc-coverage
		    EXECUTABLE bc-tests-coverage
		    DEPENDENCIES bc-tests-coverage
		    DEPENDENCIES node
		)
	endif()
endif()

