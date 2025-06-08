#include "morse.h"
#include <iostream>      // Для вывода в консоль
#include <string>        // Для работы со строками
#include <vector>        // Для хранения аргументов

/**
 * @brief Основная функция программы.
 * * @param argc Количество аргументов командной строки.
 * @param argv Массив строк с аргументами.
 * @return int Код завершения программы (0 - успех, 1 - ошибка).
 */
int main(int argc, char* argv[]) {
    // Устанавливаем кодировку UTF-8 для консоли, чтобы корректно отображать
    // кириллицу в сообщениях (особенно важно для Windows).
    #ifdef _WIN32
    system("chcp 65001 > nul");
    #endif

    // --- 1. Проверка количества аргументов ---
    // Нам нужно ровно 4 аргумента:
    // argv[0] - имя программы (например, ./morse_tool)
    // argv[1] - команда ("encode" или "decode")
    // argv[2] - входной файл
    // argv[3] - выходной файл
    if (argc != 4) {
        std::cerr << "Ошибка: Неверное количество аргументов." << std::endl;
        std::cerr << "Использование:" << std::endl;
        std::cerr << "  " << argv[0] << " encode <входной_файл.txt> <выходной_файл.bin>" << std::endl;
        std::cerr << "  " << argv[0] << " decode <входной_файл.bin> <выходной_файл.txt>" << std::endl;
        return 1; // Возвращаем код ошибки
    }

    // --- 2. Извлекаем аргументы в переменные ---
    std::string command = argv[1];
    std::string inputFilePath = argv[2];
    std::string outputFilePath = argv[3];

    // --- 3. Выполняем команду ---
    if (command == "encode") {
        std::cout << "Кодирование файла: " << inputFilePath << " -> " << outputFilePath << std::endl;
        
        MorseFileOperationResult result = encodeFileToMorse(inputFilePath, outputFilePath);

        if (result.success) {
            std::cout << "Успех! " << result.message << std::endl;
        } else {
            std::cerr << "Ошибка кодирования! " << result.message << std::endl;
            return 1; // Возвращаем код ошибки
        }

    } else if (command == "decode") {
        std::cout << "Декодирование файла: " << inputFilePath << " -> " << outputFilePath << std::endl;
        
        MorseFileOperationResult result = decodeFileFromMorse(inputFilePath, outputFilePath);

        if (result.success) {
            std::cout << "Успех! " << result.message << std::endl;
        } else {
            std::cerr << "Ошибка декодирования! " << result.message << std::endl;
            return 1; // Возвращаем код ошибки
        }

    } else {
        std::cerr << "Ошибка: Неизвестная команда '" << command << "'." << std::endl;
        std::cerr << "Доступные команды: 'encode', 'decode'." << std::endl;
        return 1; // Возвращаем код ошибки
    }

    return 0; // Успешное завершение
}
