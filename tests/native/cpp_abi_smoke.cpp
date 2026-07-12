#include "certael.hpp"
#include <iostream>

int main() {
    try {
        certael::client client;
        if (client.native_handle() == nullptr) return 1;
        std::cout << "certael C++ ABI smoke passed\n";
        return 0;
    } catch (const certael::error&) {
        return 2;
    }
}
