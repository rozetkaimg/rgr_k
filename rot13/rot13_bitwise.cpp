#include "rot13_bitwise.h"
#include <fstream>
#include <sstream>
#include <vector>

const unsigned char XOR_KEY = 170;

std::string applyRot13(const std::string& text) {
    std::string result = text;
    for (char& c : result) {
        if (c >= 'a' && c <= 'z') {
            c = (c - 'a' + 13) % 26 + 'a';
        } else if (c >= 'A' && c <= 'Z') {
            c = (c - 'A' + 13) % 26 + 'A';
        }
    }
    return result;
}

std::string applyXor(const std::string& text) {
    std::string result = text;
    for (char& c : result) {
        c ^= XOR_KEY;
    }
    return result;
}

EncodedResult encodeTextRot13Xor(const std::string& text) {
    std::string rot13_text = applyRot13(text);
    std::string xor_text = applyXor(rot13_text);
    std::vector<unsigned char> binary_data(xor_text.begin(), xor_text.end());
    return {true, "", binary_data};
}

DecodedResult decodeTextRot13Xor(const std::vector<unsigned char>& data) {
    std::string xor_text(data.begin(), data.end());
    std::string rot13_text = applyXor(xor_text);
    std::string original_text = applyRot13(rot13_text);
    return {true, "", original_text};
}

FileOperationResult encodeFileRot13Xor(const std::string& inputFilePath, const std::string& outputFilePath) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) return {false, "Error: Could not open input file."};

    std::string fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());

    EncodedResult encoded = encodeTextRot13Xor(fileContent);
    if (!encoded.success) return {false, encoded.error_message};

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) return {false, "Error: Could not create output file."};
    outputFile.write(reinterpret_cast<const char*>(encoded.binary_data.data()), encoded.binary_data.size());

    return {true, "File successfully encoded."};
}

FileOperationResult decodeFileRot13Xor(const std::string& inputFilePath, const std::string& outputFilePath) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) return {false, "Error: Could not open input file."};

    std::vector<unsigned char> binaryInput((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());

    DecodedResult decoded = decodeTextRot13Xor(binaryInput);
    if (!decoded.success) return {false, decoded.error_message};

    std::ofstream outputFile(outputFilePath, std::ios::binary);
    if (!outputFile) return {false, "Error: Could not create output file."};
    outputFile << decoded.text;

    return {true, "File successfully decoded."};
}