@echo off
setlocal

echo Building GOST library...
g++ -shared -o libgost_cipher.dll gost\gost.cpp gost\gost_bridge.cpp -I./gost
if errorlevel 1 (
    echo GOST library compilation failed.
    exit /b 1
)

echo Building Morse library...
g++ -shared -o libmorse_cipher.dll morse\morse.cpp morse\morse_bridge.cpp -I./morse
if errorlevel 1 (
    echo Morse library compilation failed.
    exit /b 1
)

echo Building ROT13 library...
g++ -shared -o librot13_cipher.dll rot13\rot13_bitwise.cpp rot13\rot13_bridge.cpp -I./rot13
if errorlevel 1 (
    echo ROT13 library compilation failed.
    exit /b 1
)

echo Building main executable...
g++ main.cpp -o cipher_tool.exe -I./gost -I./morse -I./rot13
if errorlevel 1 (
    echo Main executable compilation failed.
    exit /b 1
)

echo.
echo Build successful!
echo All files have been created in the current directory.

endlocal