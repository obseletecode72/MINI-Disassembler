namespace DataTypes {
    typedef unsigned long long u64;

    struct FunctionInfo {
        std::string name;
        uintptr_t address;
        std::vector<std::pair<uintptr_t, std::string>> instructions_with_addr;
    };

    struct Block {
        std::string name;
        std::string origLabel;
        std::vector<std::pair<uintptr_t, std::string>> insts_with_addr;
        std::vector<int> succ;
    };

    struct Region {
        uintptr_t base;
        size_t size;
    };
}
