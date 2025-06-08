#include "rot13_bitwise.h"
#include <iostream>

void printUsage(const char* programName) {
    std::cerr << "Error: Invalid arguments." << std::endl;
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  " << programName << " encode <input_file> <output_file>" << std::endl;
    std::cerr << "  " << programName << " decode <input_file> <output_file>" << std::endl;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    if (argc != 4) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    std::string inputFilePath = argv[2];
    std::string outputFilePath = argv[3];

    FileOperationResult result;
    if (command == "encode") {
        result = encodeFileRot13Xor(inputFilePath, outputFilePath);
    } else if (command == "decode") {
        result = decodeFileRot13Xor(inputFilePath, outputFilePath);
    } else {
        printUsage(argv[0]);
        return 1;
    }

    if (result.success) {
        std::cout << result.message << std::endl;
    } else {
        std::cerr << result.message << std::endl;
        return 1;
    }

    return 0;
}