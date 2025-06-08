#ifndef MORSE_CODER_HPP
#define MORSE_CODER_HPP

#include <string>
#include <vector>

// Структура для хранения результата битового кодирования.
struct MorseEncodedResult {
    std::vector<unsigned char> binary_data; // Результат в виде байтов
    bool success = false;
    std::string error_message;
};

// Структура для хранения результата декодирования.
struct MorseDecodedResult {
    std::string plaintext;
    bool success = false;
    std::string error_message;
};

// Структура для хранения результата файловой операции.
struct MorseFileOperationResult {
    bool success = false;
    std::string message;
};

// Кодирует текстовую строку в битовое представление Морзе.
MorseEncodedResult encodeTextToMorse(const std::string &plaintext);

// Декодирует битовые данные Морзе в текстовую строку.
MorseDecodedResult decodeTextFromMorse(const std::vector<unsigned char> &binary_data);

// Кодирует файл в бинарный файл Морзе.
MorseFileOperationResult encodeFileToMorse(const std::string &inputFilePath,
                                           const std::string &outputFilePath);

// Декодирует бинарный файл Морзе.
MorseFileOperationResult decodeFileFromMorse(const std::string &inputFilePath,
                                             const std::string &outputFilePath);

#endif // MORSE_CODER_HPP
