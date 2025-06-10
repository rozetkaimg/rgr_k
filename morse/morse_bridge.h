#ifndef MORSE_BRIDGE_H
#define MORSE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// C-совместимые структуры для возвращаемых результатов

// Результат кодирования
typedef struct {
    unsigned char* binary_data;
    size_t data_size;
    bool success;
    char* error_message;
} MorseEncodedResultC;

// Результат декодирования
typedef struct {
    char* plaintext;
    bool success;
    char* error_message;
} MorseDecodedResultC;

// Результат файловой операции
typedef struct {
    bool success;
    char* message;
} MorseFileOperationResultC;


// Объявления экспортируемых C-функций

DLL_EXPORT MorseEncodedResultC encodeTextToMorse_C(const char* plaintext);

DLL_EXPORT MorseDecodedResultC decodeTextFromMorse_C(const unsigned char* binary_data, size_t data_size);

DLL_EXPORT MorseFileOperationResultC encodeFileToMorse_C(const char* inputFilePath, const char* outputFilePath);

DLL_EXPORT MorseFileOperationResultC decodeFileFromMorse_C(const char* inputFilePath, const char* outputFilePath);

// Функции для освобождения памяти, выделенной в C++
DLL_EXPORT void free_morse_encoded_result_C(MorseEncodedResultC* result);
DLL_EXPORT void free_morse_decoded_result_C(MorseDecodedResultC* result);
DLL_EXPORT void free_morse_file_result_C(MorseFileOperationResultC* result);


#ifdef __cplusplus
}
#endif

#endif // MORSE_BRIDGE_H
