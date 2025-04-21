namespace Analysis {

    void Initialize() {
        if (!App::State::zydis_initialized) {
            ZydisDecoderInit(&App::State::decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
            ZydisFormatterInit(&App::State::formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterSetProperty(&App::State::formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
            ZydisFormatterSetProperty(&App::State::formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
            App::State::zydis_initialized = true;
        }
    }

    void ParseIAT(HANDLE processHandle, uintptr_t moduleBase, size_t moduleSize) {
        using namespace App::State;
        resolved_iat_targets.clear();
        if (!processHandle || !moduleBase) return;

        IMAGE_DOS_HEADER dosHeader;
        if (!Memory::ReadStructure(processHandle, moduleBase, dosHeader)) return;
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return;

        IMAGE_NT_HEADERS ntHeaders;
        if (!Memory::ReadStructure(processHandle, moduleBase + dosHeader.e_lfanew, ntHeaders)) return;
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return;

        if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
            ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
            return;
        }

        uintptr_t importDescRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        size_t importDescSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        uintptr_t importDescAddr = moduleBase + importDescRVA;

        IMAGE_IMPORT_DESCRIPTOR importDescriptor;
        for (size_t offset = 0; offset < importDescSize; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
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
                    uintptr_t resolvedFuncPtr = 0;
                    if (Memory::ReadStructure(processHandle, currentIATEntryAddr, resolvedFuncPtr) && resolvedFuncPtr != 0)
                    {
                        resolved_iat_targets[resolvedFuncPtr] = dllName + "!" + funcName;
                    }
                }
            }
        }
    }

    std::vector<DataTypes::FunctionInfo> FindFunctions(HANDLE processHandle, uintptr_t baseAddress, size_t moduleSize) {
        Initialize();
        ParseIAT(processHandle, baseAddress, moduleSize);

        auto executableRegions = Memory::GetExecutableRegions(processHandle, baseAddress, moduleSize);
        std::set<uintptr_t> potentialFunctionStarts;
        std::set<uintptr_t> knownCodeLocations;

        for (const auto& region : executableRegions) {
            auto codeBytes = Memory::ReadMemory(processHandle, region.base, region.size);
            if (codeBytes.empty()) continue;

            ZydisDecodedInstruction instruction;
            ZyanUSize offset = 0;
            const ZyanUSize length = codeBytes.size();

            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&App::State::decoder, codeBytes.data() + offset, length - offset, &instruction)))
            {
                uintptr_t currentInstructionAddress = region.base + offset;
                knownCodeLocations.insert(currentInstructionAddress);

                if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
                    for (int i = 0; i < instruction.operand_count; ++i) {
                        const auto& op = instruction.operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                            uintptr_t targetAddress = 0;
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, currentInstructionAddress, &targetAddress))) {
                                for (const auto& r_check : executableRegions) {
                                    if (targetAddress >= r_check.base && targetAddress < r_check.base + r_check.size) {
                                        potentialFunctionStarts.insert(targetAddress);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                offset += instruction.length;
            }
        }

        std::vector<DataTypes::FunctionInfo> foundFunctions;
        App::State::function_address_to_name.clear();

        std::vector<uintptr_t> validStarts;
        for (uintptr_t addr : potentialFunctionStarts) {
            if (knownCodeLocations.count(addr)) {
                validStarts.push_back(addr);
            }
        }
        MODULEINFO mi;
        if (GetModuleInformation(processHandle, App::State::selected_module, &mi, sizeof(mi))) {
            uintptr_t entryPoint = (uintptr_t)mi.EntryPoint;
            if (entryPoint >= baseAddress && entryPoint < baseAddress + moduleSize) {
                for (const auto& r_check : executableRegions) {
                    if (entryPoint >= r_check.base && entryPoint < r_check.base + r_check.size && knownCodeLocations.count(entryPoint)) {
                        if (std::find(validStarts.begin(), validStarts.end(), entryPoint) == validStarts.end()) {
                            validStarts.push_back(entryPoint);
                        }
                        break;
                    }
                }
            }
        }


        std::sort(validStarts.begin(), validStarts.end());

        for (auto addr : validStarts) {
            std::stringstream ss;
            ss << "sub_" << std::hex << addr;
            std::string name = ss.str();
            foundFunctions.push_back({ name, addr, {} });
            App::State::function_address_to_name[addr] = name;
        }

        return foundFunctions;
    }

    void LoadFunctionInstructions(DataTypes::FunctionInfo& func) {
        if (!func.address || !App::State::process_handle) return;
        Initialize();

        auto executableRegions = Memory::GetExecutableRegions(App::State::process_handle, App::State::module_base, App::State::module_size);
        if (executableRegions.empty()) {
            func.instructions_with_addr.push_back({ func.address, ";; Error: Could not find executable regions for module." });
            return;
        }


        std::map<uintptr_t, ZydisDecodedInstruction> discovered_instructions;
        std::queue<uintptr_t> exploration_queue;
        std::set<uintptr_t> visited_or_queued;
        std::set<uintptr_t> jumpTargets;

        exploration_queue.push(func.address);
        visited_or_queued.insert(func.address);

        const size_t READ_CHUNK_SIZE = 256;

        while (!exploration_queue.empty()) {
            uintptr_t current_address_to_explore = exploration_queue.front();
            exploration_queue.pop();
            if (discovered_instructions.count(current_address_to_explore)) {
                continue;
            }
            std::vector<uint8_t> current_code_bytes = Memory::ReadMemory(App::State::process_handle, current_address_to_explore, READ_CHUNK_SIZE);
            if (current_code_bytes.empty()) {
                continue;
            }

            ZydisDecodedInstruction instruction;
            if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&App::State::decoder, current_code_bytes.data(), current_code_bytes.size(), &instruction)))
            {
                uintptr_t instruction_address = current_address_to_explore;
                if (instruction.length == 0 || instruction.length > current_code_bytes.size()) {
                    continue;
                }
                discovered_instructions[instruction_address] = instruction;
                bool continue_sequential = true;
                bool is_ret = (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_IRET || instruction.mnemonic == ZYDIS_MNEMONIC_IRETD || instruction.mnemonic == ZYDIS_MNEMONIC_IRETQ);

                if (is_ret) {
                    continue_sequential = false;
                }
                else if (instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                    instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                    instruction.meta.category == ZYDIS_CATEGORY_CALL)
                {
                    uintptr_t targetAddress = 0;
                    bool target_resolved = false;
                    for (int i = 0; i < instruction.operand_count; ++i) {
                        const auto& op = instruction.operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, instruction_address, &targetAddress))) {
                                target_resolved = true;
                                break;
                            }
                        }
                        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
                                uintptr_t memory_addr_ptr = 0;
                                if (op.mem.base == ZYDIS_REGISTER_RIP) {
                                    memory_addr_ptr = instruction_address + instruction.length + (uintptr_t)op.mem.disp.value;
                                }
                                else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE) {
                                    memory_addr_ptr = (uintptr_t)op.mem.disp.value;
                                }


                                if (memory_addr_ptr != 0) {
                                    if (Memory::ReadStructure(App::State::process_handle, memory_addr_ptr, targetAddress)) {
                                        target_resolved = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }


                    if (target_resolved) {
                        bool target_in_module_region = false;
                        for (const auto& r_check : executableRegions) {
                            if (targetAddress >= r_check.base && targetAddress < r_check.base + r_check.size) {
                                target_in_module_region = true;
                                break;
                            }
                        }
                        if (target_in_module_region &&
                            (App::State::function_address_to_name.count(targetAddress) && targetAddress != func.address))
                        {
                        }
                        else if (target_in_module_region) {
                            if (visited_or_queued.find(targetAddress) == visited_or_queued.end()) {
                                exploration_queue.push(targetAddress);
                                visited_or_queued.insert(targetAddress);
                                if (instruction.meta.category != ZYDIS_CATEGORY_CALL) {
                                    jumpTargets.insert(targetAddress);
                                }
                            }
                        }
                    }
                    if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                        continue_sequential = false;
                    }
                }
                if (continue_sequential) {
                    uintptr_t next_address = instruction_address + instruction.length;
                    bool next_in_module_region = false;
                    for (const auto& r_check : executableRegions) {
                        if (next_address >= r_check.base && next_address < r_check.base + r_check.size) {
                            next_in_module_region = true; break;
                        }
                    }

                    if (next_in_module_region &&
                        (!App::State::function_address_to_name.count(next_address) || next_address == func.address) &&
                        visited_or_queued.find(next_address) == visited_or_queued.end())
                    {
                        exploration_queue.push(next_address);
                        visited_or_queued.insert(next_address);
                    }
                }

            }
            else {
                continue;
            }
        }

        func.instructions_with_addr.clear();
        if (discovered_instructions.empty()) {
            func.instructions_with_addr.push_back({ func.address, ";; Error: No instructions disassembled." });
            return;
        }
        std::vector<uintptr_t> sorted_addresses;
        for (const auto& pair : discovered_instructions) {
            sorted_addresses.push_back(pair.first);
        }
        std::sort(sorted_addresses.begin(), sorted_addresses.end());
        std::map<uintptr_t, std::string> labels;
        for (auto targetAddr : jumpTargets) {
            if (discovered_instructions.count(targetAddr)) {
                std::stringstream ss;
                ss << "loc_" << std::hex << targetAddr;
                labels[targetAddr] = ss.str();
            }
        }
        std::set<uintptr_t> labels_inserted;
        for (uintptr_t current_instruction_address : sorted_addresses) {
            const auto& instruction = discovered_instructions[current_instruction_address];
            if (labels.count(current_instruction_address) && !labels_inserted.count(current_instruction_address)) {
                func.instructions_with_addr.push_back({ current_instruction_address, labels[current_instruction_address] + ":" });
                labels_inserted.insert(current_instruction_address);
            }
            char buffer[256];
            std::string final_instr_str;
            bool is_flow_control = (instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                instruction.meta.category == ZYDIS_CATEGORY_CALL);
            uintptr_t targetAddress = 0;
            bool target_resolved = false;
            bool is_call_to_iat = false;
            std::string iat_target_name = "";


            if (is_flow_control) {
                for (int i = 0; i < instruction.operand_count; ++i) {
                    const auto& op = instruction.operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &op, current_instruction_address, &targetAddress))) {
                            target_resolved = true;
                            if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && App::State::resolved_iat_targets.count(targetAddress)) {
                                is_call_to_iat = true;
                                iat_target_name = App::State::resolved_iat_targets[targetAddress];
                            }
                            break;
                        }
                    }
                    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
                        uintptr_t memory_addr_ptr = 0;
                        if (op.mem.base == ZYDIS_REGISTER_RIP) {
                            memory_addr_ptr = current_instruction_address + instruction.length + (uintptr_t)op.mem.disp.value;
                        }
                        else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE) {
                            memory_addr_ptr = (uintptr_t)op.mem.disp.value;
                        }

                        if (memory_addr_ptr != 0) {
                            uintptr_t resolved_call_target = 0;
                            if (Memory::ReadStructure(App::State::process_handle, memory_addr_ptr, resolved_call_target)) {
                                targetAddress = resolved_call_target;
                                target_resolved = true;
                                if (App::State::resolved_iat_targets.count(targetAddress)) {
                                    is_call_to_iat = true;
                                    iat_target_name = App::State::resolved_iat_targets[targetAddress];
                                }
                                break;
                            }
                        }
                    }
                }
            }
            if (target_resolved) {
                if (is_call_to_iat) {
                    std::stringstream ss;
                    ss << ZydisMnemonicGetString(instruction.mnemonic) << " " << iat_target_name;
                    final_instr_str = ss.str();
                }
                else if (App::State::function_address_to_name.count(targetAddress)) {
                    std::stringstream ss;
                    ss << ZydisMnemonicGetString(instruction.mnemonic) << " " << App::State::function_address_to_name[targetAddress];
                    final_instr_str = ss.str();
                }
                else if (labels.count(targetAddress) && instruction.meta.category != ZYDIS_CATEGORY_CALL) {
                    std::stringstream ss;
                    ss << ZydisMnemonicGetString(instruction.mnemonic) << " " << labels[targetAddress];
                    final_instr_str = ss.str();
                }
            }
            if (final_instr_str.empty()) {
                if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&App::State::formatter, &instruction, buffer, sizeof(buffer), current_instruction_address))) {
                    final_instr_str = buffer;
                }
                else {
                    final_instr_str = ";; Error formatting instruction";
                }
            }
            func.instructions_with_addr.push_back({ current_instruction_address, final_instr_str });

        }

    }

    std::vector<DataTypes::Block> BuildBlocks(const DataTypes::FunctionInfo& func) {
        std::vector<DataTypes::Block> blocks;
        std::map<std::string, int> labelNameToIndex;
        std::map<uintptr_t, int> addressToBlockIndex;
        std::map<uintptr_t, std::string> addressToLabelName;
        int blockCounter = 0;
        int currentBlockIndex = -1;

        if (func.instructions_with_addr.empty()) return blocks;

        std::set<uintptr_t> block_leaders;
        block_leaders.insert(func.address);


        for (size_t i = 0; i < func.instructions_with_addr.size(); ++i) {
            const auto& instrPair = func.instructions_with_addr[i];
            const std::string& line = instrPair.second;
            uintptr_t currentAddr = instrPair.first;

            if (line.empty()) continue;


            if (line.back() == ':') {
                std::string labelName = line.substr(0, line.length() - 1);
                addressToLabelName[currentAddr] = labelName;
                block_leaders.insert(currentAddr);
                continue;
            }


            std::string mnemonic;
            std::string operands;
            size_t firstSpace = line.find(' ');
            if (firstSpace != std::string::npos) {
                mnemonic = line.substr(0, firstSpace);
                operands = line.substr(firstSpace + 1);
            }
            else {
                mnemonic = line;
            }
            std::string lower_mnemonic = mnemonic;
            std::transform(lower_mnemonic.begin(), lower_mnemonic.end(), lower_mnemonic.begin(), ::tolower);


            bool is_jump = (lower_mnemonic == "jmp" || (lower_mnemonic.length() > 1 && lower_mnemonic[0] == 'j' && lower_mnemonic != "jecxz"));
            bool is_call = (lower_mnemonic == "call");
            bool is_ret = (lower_mnemonic == "ret" || lower_mnemonic == "iret" || lower_mnemonic == "iretd" || lower_mnemonic == "iretq");
            bool is_unconditional_flow_change = (lower_mnemonic == "jmp" || is_ret);


            if (is_jump || is_call) {
                size_t labelPos = operands.find("loc_");
                size_t funcNamePos = operands.find("sub_");
                size_t iatNamePos = operands.find("!");

                if (labelPos != std::string::npos) {
                    std::string label = operands.substr(labelPos);
                    size_t spacePos = label.find(' ');
                    if (spacePos != std::string::npos) label = label.substr(0, spacePos);
                    try {
                        uintptr_t targetAddr = std::stoull(label.substr(4), nullptr, 16);
                        block_leaders.insert(targetAddr);
                        addressToLabelName[targetAddr] = label;
                    }
                    catch (...) {}
                }
                else if (funcNamePos != std::string::npos && is_jump) {
                    std::string funcName = operands.substr(funcNamePos);
                    size_t spacePos = funcName.find(' ');
                    if (spacePos != std::string::npos) funcName = funcName.substr(0, spacePos);
                    for (const auto& f_info : App::State::functions) {
                        if (f_info.name == funcName) {
                            block_leaders.insert(f_info.address);
                            addressToLabelName[f_info.address] = funcName;
                            break;
                        }
                    }
                }
                else if (iatNamePos != std::string::npos && is_call) {
                }
                else {
                }


                if (i + 1 < func.instructions_with_addr.size()) {
                    block_leaders.insert(func.instructions_with_addr[i + 1].first);
                }
            }
            else if (is_ret) {
                if (i + 1 < func.instructions_with_addr.size()) {
                    block_leaders.insert(func.instructions_with_addr[i + 1].first);
                }
            }
        }


        std::vector<uintptr_t> sorted_leaders(block_leaders.begin(), block_leaders.end());
        std::sort(sorted_leaders.begin(), sorted_leaders.end());


        std::map<uintptr_t, size_t> instruction_addr_to_index;
        for (size_t i = 0; i < func.instructions_with_addr.size(); ++i) {
            instruction_addr_to_index[func.instructions_with_addr[i].first] = i;
        }

        std::map<uintptr_t, int> leader_addr_to_block_idx;


        for (size_t i = 0; i < sorted_leaders.size(); ++i) {
            uintptr_t block_start_addr = sorted_leaders[i];
            if (!instruction_addr_to_index.count(block_start_addr)) continue;

            uintptr_t block_end_addr_exclusive = (i + 1 < sorted_leaders.size()) ? sorted_leaders[i + 1] : std::numeric_limits<uintptr_t>::max();


            blockCounter++;
            std::string blockName = "b" + std::to_string(blockCounter);
            std::string originalLabel = "";
            if (addressToLabelName.count(block_start_addr)) {
                originalLabel = addressToLabelName[block_start_addr];
            }
            else if (block_start_addr == func.address) {
                originalLabel = func.name;
            }


            DataTypes::Block current_block;
            current_block.name = blockName;
            current_block.origLabel = originalLabel;

            size_t start_instr_idx = instruction_addr_to_index[block_start_addr];
            size_t end_instr_idx = func.instructions_with_addr.size();
            if (block_end_addr_exclusive != std::numeric_limits<uintptr_t>::max() && instruction_addr_to_index.count(block_end_addr_exclusive)) {
                end_instr_idx = instruction_addr_to_index[block_end_addr_exclusive];
            }


            for (size_t instr_idx = start_instr_idx; instr_idx < end_instr_idx; ++instr_idx) {
                const auto& instrPair = func.instructions_with_addr[instr_idx];
                if (instrPair.second.empty() || instrPair.second.back() != ':') {
                    current_block.insts_with_addr.push_back(instrPair);
                }
                addressToBlockIndex[instrPair.first] = blocks.size();
            }


            if (!current_block.insts_with_addr.empty() || !originalLabel.empty()) {
                int current_block_idx = blocks.size();
                blocks.push_back(current_block);
                leader_addr_to_block_idx[block_start_addr] = current_block_idx;
                if (!originalLabel.empty()) {
                    labelNameToIndex[originalLabel] = current_block_idx;
                }
            }
            else {
                blockCounter--;
            }
        }



        for (int i = 0; i < (int)blocks.size(); ++i) {
            if (blocks[i].insts_with_addr.empty()) {
                continue;
            }

            const auto& lastInstructionPair = blocks[i].insts_with_addr.back();
            std::string lastInstruction = lastInstructionPair.second;
            uintptr_t lastInstructionAddr = lastInstructionPair.first;


            std::string mnemonic, operands;
            size_t firstSpace = lastInstruction.find(' ');
            if (firstSpace != std::string::npos) {
                mnemonic = lastInstruction.substr(0, firstSpace);
                operands = lastInstruction.substr(firstSpace + 1);
            }
            else {
                mnemonic = lastInstruction;
            }
            std::string lower_mnemonic = mnemonic;
            std::transform(lower_mnemonic.begin(), lower_mnemonic.end(), lower_mnemonic.begin(), ::tolower);


            bool is_cond_jump = (lower_mnemonic.length() > 1 && lower_mnemonic[0] == 'j' && lower_mnemonic != "jmp" && lower_mnemonic != "jecxz");
            bool is_jmp = (lower_mnemonic == "jmp");
            bool is_ret = (lower_mnemonic == "ret" || lower_mnemonic == "iret" || lower_mnemonic == "iretd" || lower_mnemonic == "iretq");
            bool is_call = (lower_mnemonic == "call");
            bool falls_through = !is_jmp && !is_ret;

            uintptr_t targetAddr = 0;
            bool jumpTargetFound = false;
            std::string targetLabelName = "";
            int targetBlockIndex = -1;

            if (is_jmp || is_cond_jump) {
                size_t labelPos = operands.find("loc_");
                size_t funcNamePos = operands.find("sub_");
                if (labelPos != std::string::npos) {
                    targetLabelName = operands.substr(labelPos);
                    size_t spacePos = targetLabelName.find(' ');
                    if (spacePos != std::string::npos) targetLabelName = targetLabelName.substr(0, spacePos);
                    if (labelNameToIndex.count(targetLabelName)) {
                        targetBlockIndex = labelNameToIndex[targetLabelName];
                        jumpTargetFound = true;
                    }
                }
                else if (funcNamePos != std::string::npos) {
                    targetLabelName = operands.substr(funcNamePos);
                    size_t spacePos = targetLabelName.find(' ');
                    if (spacePos != std::string::npos) targetLabelName = targetLabelName.substr(0, spacePos);
                    if (labelNameToIndex.count(targetLabelName)) {
                        targetBlockIndex = labelNameToIndex[targetLabelName];
                        jumpTargetFound = true;
                    }
                }
            }

            if (jumpTargetFound && targetBlockIndex >= 0) {
                blocks[i].succ.push_back(targetBlockIndex);
            }


            if (falls_through) {
                uintptr_t nextPossibleAddr = 0;
                if (instruction_addr_to_index.count(lastInstructionAddr)) {
                    size_t last_instr_idx = instruction_addr_to_index[lastInstructionAddr];
                    if (last_instr_idx + 1 < func.instructions_with_addr.size()) {
                        nextPossibleAddr = func.instructions_with_addr[last_instr_idx + 1].first;
                    }
                }
                if (nextPossibleAddr != 0 && leader_addr_to_block_idx.count(nextPossibleAddr)) {
                    int fallthroughBlockIndex = leader_addr_to_block_idx[nextPossibleAddr];
                    if (fallthroughBlockIndex >= 0 && fallthroughBlockIndex < (int)blocks.size()) {
                        blocks[i].succ.push_back(fallthroughBlockIndex);
                    }
                }
                /*
                else if (i + 1 < (int)blocks.size()) {
                    blocks[i].succ.push_back(i + 1);
                }
                */
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
            if (title.length() > 50) title = title.substr(0, 47) + "...";
            App::State::block_titles[b.name] = title;
            App::State::block_instructions[b.name] = b.insts_with_addr;

            dot << "    \"" << b.name << "\" [label=\"";
            std::string escaped_label_content;

            std::string escaped_title;
            for (char c : title) {
                if (c == '"' || c == '\\' || c == '{' || c == '}' || c == '|' || c == '<' || c == '>') escaped_title += '\\';
                escaped_title += c;
            }
            escaped_label_content += "{ " + escaped_title + ":\\n|";
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
            if (!instructions_part.empty()) {
                if (instructions_part.length() >= 2)
                    instructions_part.resize(instructions_part.length() - 2);
            }

            escaped_label_content += instructions_part;
            escaped_label_content += "}\"];\n";
            dot << escaped_label_content;
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
        using namespace App::State;
        std::string dot = GenerateDot(blocks);

        GVC_t* gvc = gvContext();
        if (!gvc) {
            std::cerr << "Error: Failed to create Graphviz context." << std::endl;
            return false;
        }
        Agraph_t* g = agmemread(dot.c_str());

        bool layoutSuccess = false;
        if (!g) {
            std::cerr << "Error: Could not read graph from DOT string." << std::endl;
            if (const char* err = aglasterr()) std::cerr << "Graphviz error: " << err << std::endl;
        }
        else {
            if (gvLayout(gvc, g, "dot") == 0) {
                node_positions.clear();
                node_sizes.clear();
                edges.clear();
                edge_curves.clear();

                double graphHeight = GD_bb(g).UR.y - GD_bb(g).LL.y;

                for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) {
                    char* name = agnameof(n);
                    if (!name || std::string(name).empty()) continue;
                    pointf pos = ND_coord(n);
                    double width = ND_width(n) * 72.0;
                    double height = ND_height(n) * 72.0;

                    node_positions[name] = ImVec2((float)pos.x, (float)-pos.y);
                    node_sizes[name] = ImVec2((float)width, (float)height);
                }

                for (Agnode_t* n = agfstnode(g); n; n = agnxtnode(g, n)) {
                    for (Agedge_t* e = agfstout(g, n); e; e = agnxtout(g, e)) {
                        Agnode_t* from_node = agtail(e); Agnode_t* to_node = aghead(e);
                        char* from_name = agnameof(from_node); char* to_name = agnameof(to_node);
                        if (!from_name || !to_name || std::string(from_name).empty() || std::string(to_name).empty()) continue;

                        edges.push_back({ from_name, to_name });

                        if (ED_spl(e)) {
                            splines* spl = ED_spl(e);
                            std::vector<std::array<ImVec2, 4>> curves;
                            if (spl && spl->list && spl->size > 0) {
                                for (int k = 0; k < spl->size; ++k) {
                                    bezier bez = spl->list[k];
                                    if (bez.list && bez.size >= 4 && bez.size % 3 == 1) {
                                        for (int i = 0; i < bez.size - 1; i += 3) {
                                            curves.push_back({ {
                                                ImVec2((float)bez.list[i].x,   (float)-bez.list[i].y),
                                                ImVec2((float)bez.list[i + 1].x, (float)-bez.list[i + 1].y),
                                                ImVec2((float)bez.list[i + 2].x, (float)-bez.list[i + 2].y),
                                                ImVec2((float)bez.list[i + 3].x, (float)-bez.list[i + 3].y)
                                            } });
                                        }
                                    }
                                    else if (bez.list && bez.size == 2) {
                                        ImVec2 p0 = ImVec2((float)bez.list[0].x, (float)-bez.list[0].y);
                                        ImVec2 p1 = ImVec2((float)bez.list[1].x, (float)-bez.list[1].y);
                                        curves.push_back({ { p0, p0 + (p1 - p0) * 0.33f , p0 + (p1 - p0) * 0.66f, p1} });
                                    }
                                }
                            }
                            edge_curves[{from_name, to_name}] = curves;
                        }
                    }
                }
                gvFreeLayout(gvc, g);
                layoutSuccess = true;
            }
            else {
                std::cerr << "Error during Graphviz layout." << std::endl;
                if (const char* err = aglasterr()) std::cerr << "Graphviz error: " << err << std::endl;
            }
            agclose(g);
        }
        gvFreeContext(gvc);
        return layoutSuccess;
    }
}