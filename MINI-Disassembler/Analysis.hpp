namespace Analysis {

    using namespace App::State;
    struct PeInfo {
        uintptr_t imageBase = 0;
        IMAGE_NT_HEADERS ntHeaders;
        bool valid = false;
    };
    PeInfo ReadPeHeaders(HANDLE processHandle, uintptr_t moduleBase) {
        PeInfo peInfo;
        peInfo.imageBase = moduleBase;

        IMAGE_DOS_HEADER dosHeader;
        if (!Memory::ReadStructure(processHandle, moduleBase, dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "ReadPeHeaders: Failed to read DOS header or invalid signature at 0x" << std::hex << moduleBase << std::endl;
            return peInfo;
        }

        uintptr_t ntHeaderAddr = moduleBase + dosHeader.e_lfanew;
        if (!Memory::ReadStructure(processHandle, ntHeaderAddr, peInfo.ntHeaders) || peInfo.ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "ReadPeHeaders: Failed to read NT headers or invalid signature at 0x" << std::hex << ntHeaderAddr << std::endl;
            return peInfo;
        }
        if (peInfo.ntHeaders.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)) {
            std::cerr << "ReadPeHeaders: Invalid SizeOfOptionalHeader." << std::endl;
            return peInfo;
        }

        peInfo.valid = true;
        return peInfo;
    }
    std::set<uintptr_t> GetExportAddresses(HANDLE processHandle, const PeInfo& peInfo) {
        std::set<uintptr_t> exports;
        if (!peInfo.valid || peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            return exports;
        }

        uintptr_t exportDirRVA = peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        size_t exportDirSize = peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        uintptr_t exportDirAddr = peInfo.imageBase + exportDirRVA;
        IMAGE_EXPORT_DIRECTORY exportDirectory;

        if (!Memory::ReadStructure(processHandle, exportDirAddr, exportDirectory)) {
            std::cerr << "GetExportAddresses: Failed to read export directory at 0x" << std::hex << exportDirAddr << std::endl;
            return exports;
        }

        uintptr_t functionsAddr = peInfo.imageBase + exportDirectory.AddressOfFunctions;
        uintptr_t namesAddr = peInfo.imageBase + exportDirectory.AddressOfNames;
        uintptr_t ordinalsAddr = peInfo.imageBase + exportDirectory.AddressOfNameOrdinals;

        for (DWORD i = 0; i < exportDirectory.NumberOfFunctions; ++i) {
            uintptr_t funcRvaAddr = functionsAddr + i * sizeof(DWORD);
            DWORD funcRva = 0;
            if (Memory::ReadStructure(processHandle, funcRvaAddr, funcRva) && funcRva != 0) {
                uintptr_t funcAddr = peInfo.imageBase + funcRva;
                uintptr_t exportDirEnd = peInfo.imageBase + exportDirRVA + exportDirSize;
                if (funcAddr < peInfo.imageBase + exportDirRVA || funcAddr >= exportDirEnd) {
                    exports.insert(funcAddr);
                }
                else {
                }
            }
        }

        return exports;
    }
    std::map<uintptr_t, uintptr_t> g_address_to_function_start;
    std::set<uintptr_t> g_visited_code_addresses;
    std::vector<DataTypes::FunctionInfo> g_analyzed_functions;
    std::map<uintptr_t, std::string> g_function_address_to_name;
    std::map<uintptr_t, std::map<uintptr_t, int>> g_xrefs_data;
    std::map<uintptr_t, std::string> g_resolved_iat_targets;
    void Initialize() {
        if (!App::State::zydis_initialized) {
            ZydisDecoderInit(&App::State::decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
            ZydisFormatterInit(&App::State::formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterSetProperty(&App::State::formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
            ZydisFormatterSetProperty(&App::State::formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
            App::State::zydis_initialized = true;
        }
    }
    void ParseIAT(HANDLE processHandle, uintptr_t moduleBase, const PeInfo& peInfo) {
        g_resolved_iat_targets.clear();
        if (!processHandle || !moduleBase || !peInfo.valid) return;

        if (peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
            peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
            return;
        }

        uintptr_t importDescRVA = peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        size_t importDescSize = peInfo.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        uintptr_t importDescAddr = moduleBase + importDescRVA;

        IMAGE_IMPORT_DESCRIPTOR importDescriptor;
        for (size_t offset = 0; ; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            if (importDescAddr + offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > moduleBase + importDescRVA + importDescSize) break;

            if (!Memory::ReadStructure(processHandle, importDescAddr + offset, importDescriptor)) break;
            if (importDescriptor.OriginalFirstThunk == 0 && importDescriptor.FirstThunk == 0) break;

            if (importDescriptor.Name == 0) continue;
            std::string dllName = Memory::ReadNullTerminatedString(processHandle, moduleBase + importDescriptor.Name);
            if (dllName.empty()) continue;

            uintptr_t thunkRVA = (importDescriptor.OriginalFirstThunk != 0) ? importDescriptor.OriginalFirstThunk : importDescriptor.FirstThunk;
            uintptr_t thunkAddr = moduleBase + thunkRVA;
            uintptr_t iatAddr = moduleBase + importDescriptor.FirstThunk;

            IMAGE_THUNK_DATA thunkData;
            for (int i = 0; ; ++i) {
                uintptr_t currentThunkEntryAddr = thunkAddr + i * sizeof(IMAGE_THUNK_DATA);
                uintptr_t currentIATEntryAddr = iatAddr + i * sizeof(IMAGE_THUNK_DATA);

                if (!Memory::ReadStructure(processHandle, currentThunkEntryAddr, thunkData)) break;
                if (thunkData.u1.AddressOfData == 0) break;

                std::string funcName;
                if (IMAGE_SNAP_BY_ORDINAL(thunkData.u1.Ordinal)) {
                    std::stringstream ss;
                    ss << "Ordinal_" << IMAGE_ORDINAL(thunkData.u1.Ordinal);
                    funcName = ss.str();
                }
                else {
                    uintptr_t importByNameAddr = moduleBase + thunkData.u1.AddressOfData;
                    funcName = Memory::ReadNullTerminatedString(processHandle, importByNameAddr + sizeof(WORD));
                }

                if (!funcName.empty()) {
                    g_resolved_iat_targets[currentIATEntryAddr] = dllName + "!" + funcName;
                }
            }
        }
    }
    void DisassembleFunction(
        HANDLE processHandle,
        uintptr_t funcStartAddress,
        const std::vector<DataTypes::Region>& executableRegions,
        size_t moduleSize,
        uintptr_t moduleBase
        /* Removed function specific maps, using globals */
    ) {
        if (g_visited_code_addresses.count(funcStartAddress) || g_address_to_function_start.count(funcStartAddress)) {
            return;
        }
        bool in_executable = false;
        for (const auto& region : executableRegions) {
            if (funcStartAddress >= region.base && funcStartAddress < region.base + region.size) {
                in_executable = true;
                break;
            }
        }
        if (!in_executable) {
            return;
        }
        DataTypes::FunctionInfo currentFuncInfo;
        std::stringstream ss;
        ss << "sub_" << std::hex << funcStartAddress;
        currentFuncInfo.name = ss.str();
        currentFuncInfo.address = funcStartAddress;
        g_function_address_to_name[funcStartAddress] = currentFuncInfo.name;
        std::queue<uintptr_t> exploration_queue;
        std::set<uintptr_t> visited_in_this_function;

        exploration_queue.push(funcStartAddress);
        visited_in_this_function.insert(funcStartAddress);
        g_visited_code_addresses.insert(funcStartAddress);
        g_address_to_function_start[funcStartAddress] = funcStartAddress;

        const size_t READ_CHUNK_SIZE = 512;

        std::map<uintptr_t, ZydisDecodedInstruction> function_instructions_decoded;
        std::set<uintptr_t> function_jump_targets;

        while (!exploration_queue.empty()) {
            uintptr_t current_explore_addr = exploration_queue.front();
            exploration_queue.pop();
            if (function_instructions_decoded.count(current_explore_addr)) {
                continue;
            }

            std::vector<uint8_t> code_chunk = Memory::ReadMemory(processHandle, current_explore_addr, READ_CHUNK_SIZE);
            if (code_chunk.empty()) {
                continue;
            }

            ZydisDecodedInstruction instruction;
            ZyanStatus status = ZydisDecoderDecodeBuffer(&App::State::decoder, code_chunk.data(), code_chunk.size(), &instruction);

            if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
                continue;
            }
            if (instruction.length > code_chunk.size()) {
                continue;
            }
            function_instructions_decoded[current_explore_addr] = instruction;
            uintptr_t sequential_addr = current_explore_addr + instruction.length;
            uintptr_t branch_target_addr = 0;
            bool branch_target_resolved = false;

            bool is_ret = (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_IRET || instruction.mnemonic == ZYDIS_MNEMONIC_IRETD || instruction.mnemonic == ZYDIS_MNEMONIC_IRETQ);
            bool is_unconditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
            bool is_conditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR);
            bool is_call = (instruction.meta.category == ZYDIS_CATEGORY_CALL);
            if (is_unconditional_branch || is_conditional_branch || is_call) {
                for (int i = 0; i < instruction.operand_count; ++i) {
                    const auto& op = instruction.operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, current_explore_addr, &branch_target_addr))) {
                            branch_target_resolved = true;
                            break;
                        }
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        uintptr_t memory_addr_ptr = 0;
                        if (op.mem.base == ZYDIS_REGISTER_RIP) {
                            memory_addr_ptr = current_explore_addr + instruction.length + (uintptr_t)op.mem.disp.value;
                        }
                        else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE && op.mem.disp.value != 0) {
                            uintptr_t potential_abs_addr = (uintptr_t)op.mem.disp.value;
                            if (potential_abs_addr >= moduleBase && potential_abs_addr < moduleBase + moduleSize) {
                                memory_addr_ptr = potential_abs_addr;
                            }
                            else {
                                memory_addr_ptr = potential_abs_addr;
                            }
                        }

                        if (memory_addr_ptr != 0) {
                            if (is_call || is_unconditional_branch || is_conditional_branch) {
                                uintptr_t resolved_target_ptr = 0;
                                if (Memory::ReadStructure(processHandle, memory_addr_ptr, resolved_target_ptr)) {
                                    branch_target_addr = resolved_target_ptr;
                                    branch_target_resolved = true;
                                    break;
                                }
                            }
                        }
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_POINTER) {
                        branch_target_addr = (uintptr_t)op.ptr.offset;
                        branch_target_resolved = true;
                        break;
                    }
                }
            }
            bool continue_sequential = !is_ret && !is_unconditional_branch;
            if (continue_sequential) {
                if (sequential_addr >= moduleBase && sequential_addr < moduleBase + moduleSize) {
                    if (!g_visited_code_addresses.count(sequential_addr)) {
                        if (visited_in_this_function.find(sequential_addr) == visited_in_this_function.end()) {
                            exploration_queue.push(sequential_addr);
                            visited_in_this_function.insert(sequential_addr);
                            g_visited_code_addresses.insert(sequential_addr);
                            g_address_to_function_start[sequential_addr] = funcStartAddress;
                        }
                    }
                    else {
                        if (g_address_to_function_start.count(sequential_addr) && g_address_to_function_start[sequential_addr] != funcStartAddress) {
                        }
                        else {
                            if (visited_in_this_function.find(sequential_addr) == visited_in_this_function.end()) {
                                exploration_queue.push(sequential_addr);
                                visited_in_this_function.insert(sequential_addr);
                            }
                        }
                    }
                }
            }
            if (branch_target_resolved && branch_target_addr != 0) {
                if (branch_target_addr >= moduleBase && branch_target_addr < moduleBase + moduleSize) {
                    if (!is_call) {
                        function_jump_targets.insert(branch_target_addr);

                        if (!g_visited_code_addresses.count(branch_target_addr)) {
                            if (visited_in_this_function.find(branch_target_addr) == visited_in_this_function.end()) {
                                exploration_queue.push(branch_target_addr);
                                visited_in_this_function.insert(branch_target_addr);
                                g_visited_code_addresses.insert(branch_target_addr);
                                g_address_to_function_start[branch_target_addr] = funcStartAddress;
                            }
                        }
                        else {
                            if (g_address_to_function_start.count(branch_target_addr) && g_address_to_function_start[branch_target_addr] != funcStartAddress) {
                            }
                            else {
                                if (visited_in_this_function.find(branch_target_addr) == visited_in_this_function.end()) {
                                    exploration_queue.push(branch_target_addr);
                                    visited_in_this_function.insert(branch_target_addr);
                                }
                            }
                        }
                    }
                }
                else {
                }
            }
        }
        std::vector<uintptr_t> sorted_addresses;
        for (const auto& pair : function_instructions_decoded) {
            sorted_addresses.push_back(pair.first);
        }
        std::sort(sorted_addresses.begin(), sorted_addresses.end());

        std::map<uintptr_t, std::string> labels;
        for (uintptr_t targetAddr : function_jump_targets) {
            if (function_instructions_decoded.count(targetAddr)) {
                std::stringstream ss_label;
                ss_label << "loc_" << std::hex << targetAddr;
                labels[targetAddr] = ss_label.str();
            }
        }

        std::set<uintptr_t> labels_inserted;
        for (uintptr_t current_instr_addr : sorted_addresses) {
            if (current_instr_addr < funcStartAddress) continue;

            const auto& instruction = function_instructions_decoded[current_instr_addr];
            if (labels.count(current_instr_addr) && !labels_inserted.count(current_instr_addr)) {
                if (current_instr_addr != funcStartAddress) {
                    currentFuncInfo.instructions_with_addr.push_back({ current_instr_addr, labels[current_instr_addr] + ":" });
                    labels_inserted.insert(current_instr_addr);
                }
            }
            char buffer[256];
            std::string final_instr_str;

            bool is_flow_control = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                instruction.meta.category == ZYDIS_CATEGORY_CALL);

            if (is_flow_control) {
                uintptr_t targetAddress = 0;
                bool target_resolved = false;
                bool target_is_memory = false;
                uintptr_t memory_operand_addr = 0;
                for (int i = 0; i < instruction.operand_count; ++i) {
                    const auto& op = instruction.operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, current_instr_addr, &targetAddress))) {
                            target_resolved = true; break;
                        }
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        target_is_memory = true;
                        if (op.mem.base == ZYDIS_REGISTER_RIP) {
                            memory_operand_addr = current_instr_addr + instruction.length + (uintptr_t)op.mem.disp.value;
                        }
                        else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE && op.mem.disp.value != 0) {
                            memory_operand_addr = (uintptr_t)op.mem.disp.value;
                        }
                        if (memory_operand_addr != 0) {
                            if (Memory::ReadStructure(processHandle, memory_operand_addr, targetAddress)) {
                                target_resolved = true;
                            }
                        }
                        break;
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_POINTER) {
                        targetAddress = (uintptr_t)op.ptr.offset;
                        target_resolved = true; break;
                    }
                }

                if (target_resolved) {
                    bool is_call = (instruction.mnemonic == ZYDIS_MNEMONIC_CALL);
                    std::string override_operand;
                    if (is_call && target_is_memory && g_resolved_iat_targets.count(memory_operand_addr)) {
                        override_operand = g_resolved_iat_targets[memory_operand_addr];
                    }
                    else if (g_function_address_to_name.count(targetAddress)) {
                        override_operand = g_function_address_to_name[targetAddress];
                    }
                    else if (labels.count(targetAddress)) {
                        override_operand = labels[targetAddress];
                    }

                    if (!override_operand.empty()) {
                        std::stringstream ss_override;
                        ss_override << ZydisMnemonicGetString(instruction.mnemonic) << " " << override_operand;
                        final_instr_str = ss_override.str();
                    }
                }
            }

            if (final_instr_str.empty()) {
                if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&App::State::formatter, &instruction, buffer, sizeof(buffer), current_instr_addr))) {
                    final_instr_str = buffer;
                }
                else {
                    final_instr_str = ";; Error formatting instruction";
                }
            }

            currentFuncInfo.instructions_with_addr.push_back({ current_instr_addr, final_instr_str });

        }

        if (!currentFuncInfo.instructions_with_addr.empty()) {
            g_analyzed_functions.push_back(currentFuncInfo);
        }
        else {
            g_function_address_to_name.erase(funcStartAddress);
        }
    }
    void BuildCrossReferences() {
        g_xrefs_data.clear();

        for (const auto& funcInfo : g_analyzed_functions) {
            uintptr_t caller_func_start = funcInfo.address;

            for (const auto& instrPair : funcInfo.instructions_with_addr) {
                uintptr_t instr_addr = instrPair.first;
                if (instrPair.second.empty() || instrPair.second.back() == ':') continue;
                std::vector<uint8_t> temp_code = Memory::ReadMemory(App::State::process_handle, instr_addr, 16);
                if (temp_code.empty()) continue;
                ZydisDecodedInstruction instruction;
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&App::State::decoder, temp_code.data(), temp_code.size(), &instruction))) continue;

                if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
                    uintptr_t targetAddress = 0;
                    bool target_resolved = false;
                    bool target_is_memory = false;
                    uintptr_t memory_operand_addr = 0;
                    for (int i = 0; i < instruction.operand_count; ++i) {
                        const auto& op = instruction.operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, instr_addr, &targetAddress))) {
                                target_resolved = true; break;
                            }
                        }
                        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            target_is_memory = true;
                            if (op.mem.base == ZYDIS_REGISTER_RIP) {
                                memory_operand_addr = instr_addr + instruction.length + (uintptr_t)op.mem.disp.value;
                            }
                            else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE && op.mem.disp.value != 0) {
                                memory_operand_addr = (uintptr_t)op.mem.disp.value;
                            }
                            if (memory_operand_addr != 0) {
                                if (Memory::ReadStructure(App::State::process_handle, memory_operand_addr, targetAddress)) {
                                    target_resolved = true;
                                }
                            }
                            break;
                        }
                        else if (op.type == ZYDIS_OPERAND_TYPE_POINTER) {
                            targetAddress = (uintptr_t)op.ptr.offset;
                            target_resolved = true; break;
                        }
                    }

                    if (target_resolved && targetAddress != 0) {
                        uintptr_t target_func_start = 0;
                        auto it_func = g_address_to_function_start.find(targetAddress);
                        if (it_func != g_address_to_function_start.end()) {
                            target_func_start = it_func->second;
                        }
                        else {
                            if (g_function_address_to_name.count(targetAddress)) {
                                target_func_start = targetAddress;
                            }
                        }


                        if (target_func_start != 0 && g_function_address_to_name.count(target_func_start)) {
                            g_xrefs_data[target_func_start][caller_func_start]++;
                        }
                    }
                }
            }
        }
    }
    void PerformFullAnalysis(HANDLE processHandle, uintptr_t moduleBase, size_t moduleSize) {
        if (!processHandle || !moduleBase || moduleSize == 0) {
            is_analyzing = false;
            analysis_status_message = "Invalid process, module base, or size.";
            analysis_results_valid = false;
            return;
        }

        is_analyzing = true;
        analysis_status_message = "Initializing Analysis...";
        analysis_results_valid = false;
        g_analyzed_functions.clear();
        g_function_address_to_name.clear();
        g_address_to_function_start.clear();
        g_visited_code_addresses.clear();
        g_xrefs_data.clear();
        g_resolved_iat_targets.clear();
        App::State::functions.clear();
        App::State::function_address_to_name.clear();
        App::State::xrefs_data.clear();
        App::State::resolved_iat_targets.clear();
        App::State::selected_function = {};
        App::State::layout_function_address = 0;
        App::State::node_positions.clear();
        App::State::node_sizes.clear();
        App::State::edges.clear();
        App::State::edge_curves.clear();
        App::State::block_instructions.clear();
        App::State::block_titles.clear();
        App::State::show_graph_window = false;
        App::State::show_xrefs_window = false;

        Initialize();

        analysis_status_message = "Reading PE Headers...";
        PeInfo peInfo = ReadPeHeaders(processHandle, moduleBase);
        if (!peInfo.valid) {
            analysis_status_message = "Error: Failed to read PE headers.";
            is_analyzing = false;
            return;
        }

        analysis_status_message = "Parsing IAT...";
        ParseIAT(processHandle, moduleBase, peInfo);

        analysis_status_message = "Finding Executable Regions...";
        auto executableRegions = Memory::GetExecutableRegions(processHandle, moduleBase, moduleSize);
        if (executableRegions.empty()) {
            analysis_status_message = "Error: No executable regions found.";
            is_analyzing = false;
            return;
        }

        analysis_status_message = "Identifying Function Candidates...";
        std::set<uintptr_t> initial_candidates;
        if (peInfo.ntHeaders.OptionalHeader.AddressOfEntryPoint != 0) {
            uintptr_t entryPoint = moduleBase + peInfo.ntHeaders.OptionalHeader.AddressOfEntryPoint;
            if (entryPoint >= moduleBase && entryPoint < moduleBase + moduleSize) {
                initial_candidates.insert(entryPoint);
            }
        }
        std::set<uintptr_t> exports = GetExportAddresses(processHandle, peInfo);
        for (uintptr_t exp_addr : exports) {
            if (exp_addr >= moduleBase && exp_addr < moduleBase + moduleSize) {
                initial_candidates.insert(exp_addr);
            }
        }
        analysis_status_message = "Scanning for Call Targets...";
        for (const auto& region : executableRegions) {
            auto codeBytes = Memory::ReadMemory(processHandle, region.base, region.size);
            if (codeBytes.empty()) continue;

            ZydisDecodedInstruction instruction;
            ZyanUSize offset = 0;
            const ZyanUSize length = codeBytes.size();

            while (offset < length) {
                ZyanStatus status = ZydisDecoderDecodeBuffer(&App::State::decoder, codeBytes.data() + offset, length - offset, &instruction);
                if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
                    offset++;
                    continue;
                }

                uintptr_t currentInstructionAddress = region.base + offset;
                if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
                    uintptr_t targetAddress = 0;
                    bool target_resolved = false;
                    for (int i = 0; i < instruction.operand_count; ++i) {
                        const auto& op = instruction.operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, currentInstructionAddress, &targetAddress))) {
                                target_resolved = true; break;
                            }
                        }
                        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            uintptr_t mem_op_addr = 0;
                            if (op.mem.base == ZYDIS_REGISTER_RIP) {
                                mem_op_addr = currentInstructionAddress + instruction.length + (uintptr_t)op.mem.disp.value;
                            }
                            else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE && op.mem.disp.value != 0) {
                                mem_op_addr = (uintptr_t)op.mem.disp.value;
                            }
                            if (mem_op_addr != 0) {
                                uintptr_t potential_target = 0;
                                if (g_resolved_iat_targets.count(mem_op_addr)) {
                                }
                                else if (Memory::ReadStructure(processHandle, mem_op_addr, potential_target)) {
                                    targetAddress = potential_target;
                                    target_resolved = true;
                                }
                            }
                            break;
                        }
                        else if (op.type == ZYDIS_OPERAND_TYPE_POINTER) {
                            targetAddress = (uintptr_t)op.ptr.offset;
                            target_resolved = true; break;
                        }
                    }
                    if (target_resolved && targetAddress >= moduleBase && targetAddress < moduleBase + moduleSize) {
                        initial_candidates.insert(targetAddress);
                    }
                }
                offset += instruction.length;
            }
        }

        analysis_status_message = "Analyzing Code Flow...";
        std::queue<uintptr_t> analysis_queue;
        for (uintptr_t candidate : initial_candidates) {
            analysis_queue.push(candidate);
        }

        std::set<uintptr_t> processed_starts;
        size_t functions_found_count = 0;
        while (!analysis_queue.empty()) {
            uintptr_t current_start = analysis_queue.front();
            analysis_queue.pop();

            if (processed_starts.count(current_start)) continue;
            processed_starts.insert(current_start);

            if (g_address_to_function_start.count(current_start)) continue;
            if (processed_starts.size() % 200 == 0) {
                functions_found_count = g_function_address_to_name.size();
                analysis_status_message = "Analyzing Code Flow... Found " + std::to_string(functions_found_count) + " functions. Queue: " + std::to_string(analysis_queue.size());
            }

            DisassembleFunction(processHandle, current_start, executableRegions, moduleSize, moduleBase);

        }
        functions_found_count = g_function_address_to_name.size();
        std::sort(g_analyzed_functions.begin(), g_analyzed_functions.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
            });

        analysis_status_message = "Building Cross-References...";
        BuildCrossReferences();
        App::State::functions = g_analyzed_functions;
        App::State::function_address_to_name = g_function_address_to_name;
        App::State::xrefs_data = g_xrefs_data;
        App::State::resolved_iat_targets = g_resolved_iat_targets;

        if (!g_analyzed_functions.empty()) {
            analysis_results_valid = true;
            analysis_status_message = "Analysis Complete. Found " + std::to_string(functions_found_count) + " functions.";
        }
        else {
            analysis_results_valid = false;
            analysis_status_message = "Analysis Complete. No functions found.";
        }

        is_analyzing = false;
    }
    std::vector<DataTypes::Block> BuildBlocks(const DataTypes::FunctionInfo& func) {
        std::vector<DataTypes::Block> blocks;
        if (func.instructions_with_addr.empty()) return blocks;
        std::set<uintptr_t> explicit_jump_targets;

        std::map<std::string, int> labelNameToIndex;
        std::map<uintptr_t, int> addressToBlockIndex;
        std::map<uintptr_t, std::string> addressToLabelName;
        std::set<uintptr_t> block_leaders;
        block_leaders.insert(func.address);

        std::map<uintptr_t, size_t> instruction_addr_to_vector_idx;
        for (size_t i = 0; i < func.instructions_with_addr.size(); ++i) {
            instruction_addr_to_vector_idx[func.instructions_with_addr[i].first] = i;
        }
        for (size_t i = 0; i < func.instructions_with_addr.size(); ++i) {
            const auto& instrPair = func.instructions_with_addr[i];
            const std::string& line = instrPair.second;
            uintptr_t currentAddr = instrPair.first;

            if (line.empty()) continue;
            if (line.back() == ':') {
                block_leaders.insert(currentAddr);
                continue;
            }
            std::vector<uint8_t> temp_code = Memory::ReadMemory(App::State::process_handle, currentAddr, 16);
            if (temp_code.empty()) continue;
            ZydisDecodedInstruction instruction;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&App::State::decoder, temp_code.data(), temp_code.size(), &instruction))) continue;

            bool is_ret = (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_IRET || instruction.mnemonic == ZYDIS_MNEMONIC_IRETD || instruction.mnemonic == ZYDIS_MNEMONIC_IRETQ);
            bool is_unconditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
            bool is_conditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR);
            bool is_call = (instruction.meta.category == ZYDIS_CATEGORY_CALL);
            bool ends_basic_block = is_ret || is_unconditional_branch || is_conditional_branch || is_call;

            if (is_unconditional_branch || is_conditional_branch) {
                uintptr_t targetAddr = 0;
                bool targetResolved = false;
                for (int op_idx = 0; op_idx < instruction.operand_count; ++op_idx) {
                    const auto& op = instruction.operands[op_idx];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, currentAddr, &targetAddr))) {
                            targetResolved = true; break;
                        }
                    }
                }
                size_t labelPos = line.find("loc_");
                if (!targetResolved && labelPos != std::string::npos) { /* ... (parsing logic) ... */
                    size_t firstSpace = line.find(' ');
                    std::string operandStr = (firstSpace != std::string::npos) ? line.substr(firstSpace + 1) : "";
                    if (operandStr.rfind("loc_", 0) == 0) {
                        std::string targetLabelName = operandStr;
                        targetLabelName = targetLabelName.substr(0, targetLabelName.find_first_of(" ;,"));
                        try {
                            if (targetLabelName.length() > 4) {
                                targetAddr = std::stoull(targetLabelName.substr(4), nullptr, 16);
                                targetResolved = true;
                            }
                        }
                        catch (...) { /* ignore */ }
                    }
                }


                if (targetResolved && instruction_addr_to_vector_idx.count(targetAddr)) {
                    block_leaders.insert(targetAddr);
                    explicit_jump_targets.insert(targetAddr);
                }
            }
            if (ends_basic_block) {
                if (i + 1 < func.instructions_with_addr.size()) {
                    uintptr_t nextAddr = func.instructions_with_addr[i + 1].first;
                    block_leaders.insert(nextAddr);
                }
            }
        }
        for (uintptr_t targetAddr : explicit_jump_targets) {
            std::stringstream ss_label;
            ss_label << "loc_" << std::hex << targetAddr;
            addressToLabelName[targetAddr] = ss_label.str();
        }
        std::vector<uintptr_t> sorted_leaders(block_leaders.begin(), block_leaders.end());
        std::sort(sorted_leaders.begin(), sorted_leaders.end());

        sorted_leaders.erase(std::remove_if(sorted_leaders.begin(), sorted_leaders.end(),
            [&](uintptr_t addr) { return !instruction_addr_to_vector_idx.count(addr); }),
            sorted_leaders.end());


        std::map<uintptr_t, int> leader_addr_to_block_idx;
        for (size_t i = 0; i < sorted_leaders.size(); ++i) {
            uintptr_t block_start_addr = sorted_leaders[i];
            size_t start_instr_idx = instruction_addr_to_vector_idx[block_start_addr];

            size_t end_instr_idx_exclusive = func.instructions_with_addr.size();
            if (i + 1 < sorted_leaders.size()) {
                uintptr_t next_leader_addr = sorted_leaders[i + 1];
                if (instruction_addr_to_vector_idx.count(next_leader_addr)) {
                    end_instr_idx_exclusive = instruction_addr_to_vector_idx[next_leader_addr];
                }
            }

            DataTypes::Block current_block;
            std::string blockName = "block_" + std::to_string(blocks.size());
            current_block.name = blockName;
            std::string originalLabel = "";
            if (block_start_addr == func.address) {
                originalLabel = func.name;
            }
            else if (explicit_jump_targets.count(block_start_addr)) {
                if (addressToLabelName.count(block_start_addr)) {
                    originalLabel = addressToLabelName[block_start_addr];
                }
                else {
                    std::stringstream ss_fallback; ss_fallback << "loc_" << std::hex << block_start_addr;
                    originalLabel = ss_fallback.str();
                    std::cerr << "Warning: Explicit jump target 0x" << std::hex << block_start_addr << " missing from addressToLabelName map." << std::endl;
                }
            }
            current_block.origLabel = originalLabel;
            for (size_t instr_idx = start_instr_idx; instr_idx < end_instr_idx_exclusive; ++instr_idx) {
                const auto& instrPair = func.instructions_with_addr[instr_idx];
                if (instrPair.second.empty() || instrPair.second.back() != ':') {
                    current_block.insts_with_addr.push_back(instrPair);
                }
                addressToBlockIndex[instrPair.first] = blocks.size();
            }


            if (!current_block.insts_with_addr.empty()) {
                int current_block_idx = blocks.size();
                leader_addr_to_block_idx[block_start_addr] = current_block_idx;
                if (!current_block.origLabel.empty()) {
                    labelNameToIndex[current_block.origLabel] = current_block_idx;
                }
                blocks.push_back(current_block);
            }
        }
        for (int i = 0; i < (int)blocks.size(); ++i) {
            if (blocks[i].insts_with_addr.empty()) continue;

            const auto& lastInstructionPair = blocks[i].insts_with_addr.back();
            uintptr_t lastInstructionAddr = lastInstructionPair.first;
            const std::string& lastInstructionStr = lastInstructionPair.second;

            std::vector<uint8_t> temp_code = Memory::ReadMemory(App::State::process_handle, lastInstructionAddr, 16);
            if (temp_code.empty()) continue;
            ZydisDecodedInstruction instruction;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&App::State::decoder, temp_code.data(), temp_code.size(), &instruction))) continue;

            bool is_ret = (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_IRET || instruction.mnemonic == ZYDIS_MNEMONIC_IRETD || instruction.mnemonic == ZYDIS_MNEMONIC_IRETQ);
            bool is_unconditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
            bool is_conditional_branch = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR);

            bool falls_through = !is_ret && !is_unconditional_branch;
            if (is_unconditional_branch || is_conditional_branch) {
                uintptr_t targetAddr = 0;
                bool targetResolved = false;
                for (int op_idx = 0; op_idx < instruction.operand_count; ++op_idx) {
                    const auto& op = instruction.operands[op_idx];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, lastInstructionAddr, &targetAddr))) {
                            targetResolved = true; break;
                        }
                    }
                }
                size_t labelPos = lastInstructionStr.find("loc_");
                if (!targetResolved && labelPos != std::string::npos) { /* ... (parsing logic) ... */
                    size_t firstSpace = lastInstructionStr.find(' ');
                    std::string operandStr = (firstSpace != std::string::npos) ? lastInstructionStr.substr(firstSpace + 1) : "";
                    if (operandStr.rfind("loc_", 0) == 0) {
                        std::string targetLabelName = operandStr;
                        targetLabelName = targetLabelName.substr(0, targetLabelName.find_first_of(" ;,"));
                        try {
                            if (targetLabelName.length() > 4) {
                                targetAddr = std::stoull(targetLabelName.substr(4), nullptr, 16);
                                targetResolved = true;
                            }
                        }
                        catch (...) { /* ignore */ }
                    }
                }


                if (targetResolved && leader_addr_to_block_idx.count(targetAddr)) {
                    int targetBlockIndex = leader_addr_to_block_idx[targetAddr];
                    blocks[i].succ.push_back(targetBlockIndex);
                }
            }
            if (falls_through) {
                if (instruction_addr_to_vector_idx.count(lastInstructionAddr)) {
                    size_t last_instr_vec_idx = instruction_addr_to_vector_idx[lastInstructionAddr];
                    if (last_instr_vec_idx + 1 < func.instructions_with_addr.size()) {
                        uintptr_t fallthroughAddr = func.instructions_with_addr[last_instr_vec_idx + 1].first;
                        if (leader_addr_to_block_idx.count(fallthroughAddr)) {
                            int fallthroughBlockIndex = leader_addr_to_block_idx[fallthroughAddr];
                            bool already_added = false;
                            for (int succ_idx : blocks[i].succ) { if (succ_idx == fallthroughBlockIndex) { already_added = true; break; } }
                            if (!already_added) {
                                blocks[i].succ.push_back(fallthroughBlockIndex);
                            }
                        }
                    }
                }
            }

            std::sort(blocks[i].succ.begin(), blocks[i].succ.end());
            blocks[i].succ.erase(std::unique(blocks[i].succ.begin(), blocks[i].succ.end()), blocks[i].succ.end());
        }

        return blocks;
    }
    std::string GenerateDot(const std::vector<DataTypes::Block>& blocks) {
        std::stringstream dot;
        dot << "digraph G {\n";
        dot << "    graph [splines=ortho, nodesep=1, ranksep=1.5];\n";
        dot << "    node [shape=record, fontname=\"Courier New\", fontsize=10, style=filled, fillcolor=\"#2D2D32\", fontcolor=\"#D2D2D2\"];\n";
        dot << "    edge [color=\"#C8C8C8\"];\n";

        App::State::block_titles.clear();
        App::State::block_instructions.clear();

        for (const auto& b : blocks) {
            std::string title = b.origLabel.empty() ? b.name : b.origLabel;

            App::State::block_titles[b.name] = title;
            App::State::block_instructions[b.name] = b.insts_with_addr;
            std::string escaped_title;
            for (char c : title) {
                if (c == '"' || c == '\\' || c == '{' || c == '}' || c == '|' || c == '<' || c == '>') escaped_title += '\\';
                escaped_title += c;
            }

            dot << "    \"" << b.name << "\" [label=\"";
            dot << "{ " << escaped_title << " |";

            std::string instructions_part;
            for (const auto& instPair : b.insts_with_addr) {
                std::string line_content;
                if (App::State::show_instruction_addresses) {
                    std::stringstream ss_addr;
                    ss_addr << "0x" << std::hex << std::setw(16) << std::setfill('0') << instPair.first << "  ";
                    line_content += ss_addr.str();
                }
                std::string escaped_inst;
                for (char c : instPair.second) {
                    if (c == '"' || c == '\\' || c == '{' || c == '}' || c == '|' || c == '<' || c == '>') escaped_inst += '\\';
                    else escaped_inst += c;
                }
                line_content += escaped_inst;
                instructions_part += line_content + "\\l";
            }
            if (!instructions_part.empty() && instructions_part.length() >= 2) {
                instructions_part.pop_back(); instructions_part.pop_back();
            }

            dot << instructions_part;
            dot << "}\"];\n";
        }

        for (size_t i = 0; i < blocks.size(); ++i) {
            for (int s : blocks[i].succ) {
                if (s >= 0 && s < (int)blocks.size()) {
                    dot << "    \"" << blocks[i].name << "\" -> \"" << blocks[s].name << "\";\n";
                }
            }
        }

        dot << "}\n";
        return dot.str();
    }
    bool CalculateLayout(const std::vector<DataTypes::Block>& blocks) {
        if (blocks.empty()) { /* ... */ return false; }
        std::string dot = GenerateDot(blocks);
        if (dot.empty()) { /* ... */ return false; }
        GVC_t* gvc = gvContext();
        if (!gvc) { /* ... */ return false; }
        Agraph_t* g = agmemread(dot.c_str());
        if (!g) { /* ... */ gvFreeContext(gvc); return false; }

        bool layoutSuccess = false;
        if (gvLayout(gvc, g, "dot") == 0) {
            App::State::node_positions.clear();
            App::State::node_sizes.clear();
            App::State::edges.clear();
            App::State::edge_curves.clear();
            for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) { /* ... */
                char* name = agnameof(n); if (!name || std::string(name).empty()) continue;
                pointf pos = ND_coord(n); double width = ND_width(n); double height = ND_height(n);
                App::State::node_positions[name] = ImVec2((float)pos.x, (float)-pos.y);
                App::State::node_sizes[name] = ImVec2((float)(width * 72.0), (float)(height * 72.0));
            }
            for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) {
                for (Agedge_t* e = agfstout(g, n); e; e = agnxtout(g, e)) { /* ... */
                    Agnode_t* from_node = agtail(e); Agnode_t* to_node = aghead(e);
                    char* from_name = agnameof(from_node); char* to_name = agnameof(to_node);
                    if (!from_name || !to_name || std::string(from_name).empty() || std::string(to_name).empty()) continue;
                    App::State::edges.push_back({ from_name, to_name });
                    auto edge_key = std::make_pair<std::string, std::string>(from_name, to_name);
                    App::State::edge_curves[edge_key] = {};
                    if (ED_spl(e)) {
                        splines* spl = ED_spl(e);
                        if (spl && spl->list && spl->size > 0) {
                            for (int k = 0; k < spl->size; ++k) {
                                bezier bez = spl->list[k];
                                if (bez.list && bez.size >= 4 && bez.size % 3 == 1) {
                                    for (int i = 0; i < bez.size - 1; i += 3) {
                                        std::array<ImVec2, 4> curve_segment = { { /* ... points ... */
                                            ImVec2((float)bez.list[i].x,   (float)-bez.list[i].y),
                                            ImVec2((float)bez.list[i + 1].x, (float)-bez.list[i + 1].y),
                                            ImVec2((float)bez.list[i + 2].x, (float)-bez.list[i + 2].y),
                                            ImVec2((float)bez.list[i + 3].x, (float)-bez.list[i + 3].y)
                                        } };
                                        App::State::edge_curves[edge_key].push_back(curve_segment);
                                    }
                                }
                                else if (bez.list && bez.size == 2) { /* ... handle lines ... */
                                    ImVec2 p0 = ImVec2((float)bez.list[0].x, (float)-bez.list[0].y);
                                    ImVec2 p1 = ImVec2((float)bez.list[1].x, (float)-bez.list[1].y);
                                    std::array<ImVec2, 4> line_segment = { { p0, p0 + (p1 - p0) * 0.33f , p0 + (p1 - p0) * 0.66f, p1} };
                                    App::State::edge_curves[edge_key].push_back(line_segment);
                                }
                            }
                        }
                    }
                }
            }
            gvFreeLayout(gvc, g);
            layoutSuccess = true;
        }
        else { /* ... error handling ... */ }
        agclose(g); gvFreeContext(gvc);
        return layoutSuccess;
    }
    void LoadFunctionInstructions(DataTypes::FunctionInfo& func) {
        for (const auto& analyzed_func : g_analyzed_functions) {
            if (analyzed_func.address == func.address) {
                func.instructions_with_addr = analyzed_func.instructions_with_addr;
                func.name = analyzed_func.name;
                return;
            }
        }
        func.instructions_with_addr.clear();
        func.instructions_with_addr.push_back({ func.address, ";; Error: Function not found in analysis results." });
    }
}