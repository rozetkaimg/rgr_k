@echo off
setlocal

set CMAKE_GENERATOR="Visual Studio 17 2022"
cmake --version >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ОШИБКА: CMake не найден.
    echo Пожалуйста, установите CMake и убедитесь, что он добавлен в PATH.
    echo.
    exit /b 1
)

echo Создание директории 'build'...
if not exist build mkdir build
cd build
echo.
echo Запуск CMake для генерации проекта %CMAKE_GENERATOR%...
cmake .. -G %CMAKE_GENERATOR%
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ОШИБКА: Не удалось выполнить команду CMake.
    echo Убедитесь, что Visual Studio установлена корректно.
    echo.
    exit /b %ERRORLEVEL%
)
echo.
echo Сборка проекта...
cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ОШИБКА: Сборка проекта не удалась.
    echo.
    exit /b %ERRORLEVEL%
)

echo.
echo -------------------------------------
echo Сборка успешно завершена!
echo.
echo Исполняемый файл 'cipher_tool.exe' и библиотеки (.dll) находятся в директории:
echo %cd%\Release
echo -------------------------------------

endlocal