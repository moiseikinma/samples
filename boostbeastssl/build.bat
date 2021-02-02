cmake -G "Visual Studio 16 2019" .. -B build -S . -DCMAKE_TOOLCHAIN_FILE=..\..\..\..\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
cmake --build build --config Debug