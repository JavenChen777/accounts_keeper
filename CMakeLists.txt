cmake_minimum_required(VERSION 3.20)

project(AccountsKeeper LANGUAGES CXX)

add_executable(AccountsKeeper WIN32
    src/main.cpp
    src/AccountsKeeper.rc
)

target_compile_features(AccountsKeeper PRIVATE cxx_std_17)
target_compile_definitions(AccountsKeeper PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(AccountsKeeper PRIVATE
    advapi32
    bcrypt
    comctl32
    crypt32
    gdi32
    ole32
    shell32
    shlwapi
    user32
    winhttp
)
