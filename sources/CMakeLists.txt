# add subdirectory libraries

include_directories(
    ../include
    ../libraries
    ../sources
    ../interfaces
    ../libraries/tomlplusplus/include
)

add_subdirectory(crowsocket)
add_subdirectory(../libraries/crow libraries/crow)
add_subdirectory(../libraries/tomlplusplus libraries/tomlplusplus)