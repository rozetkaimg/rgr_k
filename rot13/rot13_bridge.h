#ifndef ROT13_BRIDGE_H
#define ROT13_BRIDGE_H

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

typedef struct {
    bool success;
    char* error_message;
    unsigned char* binary_data;
    size_t data_size;
} EncodedResultC;

typedef struct {
    bool success;
    char* error_message;
    char* text;
} DecodedResultC;

typedef struct {
    bool success;
    char* message;
} FileOperationResultC;

// Объявления экспортируемых C-функций

DLL_EXPORT EncodedResultC encodeTextRot13Xor_C(const char* text);
DLL_EXPORT DecodedResultC decodeTextRot13Xor_C(const unsigned char* data, size_t data_size);
DLL_EXPORT FileOperationResultC encodeFileRot13Xor_C(const char* inputFilePath, const char* outputFilePath);
DLL_EXPORT FileOperationResultC decodeFileRot13Xor_C(const char* inputFilePath, const char* outputFilePath);

// Функции для освобождения памяти, выделенной внутри библиотеки
DLL_EXPORT void free_rot13_encoded_result_C(EncodedResultC* result);
DLL_EXPORT void free_rot13_decoded_result_C(DecodedResultC* result);
DLL_EXPORT void free_rot13_file_result_C(FileOperationResultC* result);

#ifdef __cplusplus
}
#endif

#endif // ROT13_BRIDGE_H
