#ifndef GOST_BRIDGE_H
#define GOST_BRIDGE_H

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Structures for C API
struct GostEncryptedTextResultC {
    char* iv_hex;
    char* ciphertext_hex;
    bool success;
    char* error_message;
};

struct GostDecryptedTextResultC {
    char* plaintext;
    bool success;
    char* error_message;
};

struct GostFileOperationResultC {
    bool success;
    char* message;
    char* used_iv_hex;
};

DLL_EXPORT GostEncryptedTextResultC encryptTextGOST_C(const char* plaintext,
                                                    const char* key_hex,
                                                    const char* iv_hex);

DLL_EXPORT GostDecryptedTextResultC decryptTextGOST_C(const char* iv_hex,
                                                    const char* ciphertext_hex,
                                                    const char* key_hex);

DLL_EXPORT GostFileOperationResultC encryptFileGOST_C(const char* inputFilePath,
                                                    const char* outputFilePath,
                                                    const char* key_hex,
                                                    const char* initial_iv_hex);

DLL_EXPORT GostFileOperationResultC decryptFileGOST_C(const char* inputFilePath,
                                                    const char* outputFilePath,
                                                    const char* key_hex);

DLL_EXPORT void free_gost_string_C(char* str);

#ifdef __cplusplus
}
#endif

#endif // GOST_BRIDGE_H
