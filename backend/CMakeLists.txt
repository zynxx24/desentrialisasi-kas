cmake_minimum_required(VERSION 3.14)
project(MyProject)

# Aktifkan C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Integrasikan Conan
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

# Tambahkan modul menggunakan FetchContent (opsional, jika diperlukan pustaka lain)
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Tambahkan target utama
add_executable(MyApp src/main.cpp)

# Hubungkan pustaka Conan dan FetchContent
target_link_libraries(MyApp PRIVATE ${CONAN_LIBS} gtest_main)
