#!/bin/bash

# Прекратить выполнение при любой ошибке
set -e

echo "Сборка библиотеки GOST..."
g++ -shared -fPIC -o libgost_cipher.so gost/gost.cpp gost/gost_bridge.cpp -I./gost

echo "Сборка библиотеки Morse..."
g++ -shared -fPIC -o libmorse_cipher.so morse/morse.cpp morse/morse_bridge.cpp -I./morse

echo "Сборка библиотеки ROT13..."
g++ -shared -fPIC -o librot13_cipher.so rot13/rot13_bitwise.cpp rot13/rot13_bridge.cpp -I./rot13

echo "Сборка основного исполняемого файла..."
# Флаг -ldl необходим для функций dlopen/dlsym
g++ main.cpp -o cipher_tool -ldl -I./gost -I./morse -I./rot13

echo ""
echo "Сборка успешно завершена!"
echo "Все файлы созданы в текущей директории."
