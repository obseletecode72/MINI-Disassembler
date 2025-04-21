namespace Memory {
    std::vector<DataTypes::Region> GetExecutableRegions(HANDLE processHandle, uintptr_t baseAddress, size_t regionSize) {
        std::vector<DataTypes::Region> regions;
        uintptr_t currentAddress = baseAddress;
        uintptr_t endAddress = baseAddress + regionSize;

        while (currentAddress < endAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(processHandle, (LPCVOID)currentAddress, &mbi, sizeof(mbi))) {
                break;
            }

            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
                size_t currentRegionSize = mbi.RegionSize;

                uintptr_t effectiveRegionStart = std::max(regionBase, baseAddress);
                uintptr_t effectiveRegionEnd = std::min(regionBase + currentRegionSize, endAddress);

                if (effectiveRegionEnd > effectiveRegionStart) {
                    regions.push_back({ effectiveRegionStart, effectiveRegionEnd - effectiveRegionStart });
                }
            }
            uintptr_t nextAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (nextAddress <= currentAddress) break;
            currentAddress = nextAddress;
        }
        return regions;
    }

    std::vector<uint8_t> ReadMemory(HANDLE processHandle, uintptr_t address, size_t length) {
        std::vector<uint8_t> buffer(length);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), length, &bytesRead)) {
            buffer.clear();
        }
        else {
            buffer.resize(bytesRead);
        }
        return buffer;
    }

    template<typename T>
    bool ReadStructure(HANDLE processHandle, uintptr_t address, T& structure) {
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(processHandle, (LPCVOID)address, &structure, sizeof(T), &bytesRead) && bytesRead == sizeof(T);
    }

    std::string ReadNullTerminatedString(HANDLE processHandle, uintptr_t address, size_t maxLength = 256) {
        std::string result;
        result.reserve(64);
        char c;
        SIZE_T bytesRead;
        for (size_t i = 0; i < maxLength; ++i) {
            if (!ReadProcessMemory(processHandle, (LPCVOID)(address + i), &c, 1, &bytesRead) || bytesRead != 1) {
                return "";
            }
            if (c == '\0') {
                break;
            }
            result += c;
        }
        return result;
    }
}
