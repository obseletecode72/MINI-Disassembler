#include <thread>
namespace RenderUtils {
    using namespace App::State;
    void DrawArrow(ImDrawList* draw_list, ImVec2 p, ImVec2 dir, ImU32 color, float size = 10.0f) {
        float len = sqrtf(dir.x * dir.x + dir.y * dir.y);
        if (len < 1e-6f) return;
        dir.x /= len;
        dir.y /= len;
        ImVec2 tip = p;
        ImVec2 base_mid = p - dir * size;
        ImVec2 norm_dir = ImVec2(-dir.y, dir.x);
        ImVec2 base1 = base_mid + norm_dir * (size / 2.0f);
        ImVec2 base2 = base_mid - norm_dir * (size / 2.0f);
        draw_list->AddTriangleFilled(tip, base1, base2, color);
    }
    ImVec2 ScreenToWorld(ImVec2 screen_pos, ImVec2 view_offset, float zoom) {
        if (fabs(zoom) < 1e-6f) return ImVec2(0, 0);
        return (screen_pos - view_offset) / zoom;
    }
    ImVec2 WorldToScreen(ImVec2 world_pos, ImVec2 view_offset, float zoom) {
        return (world_pos * zoom) + view_offset;
    }
    ImU32 GetInstructionColor(const std::string& instruction_line) {
        size_t firstSpace = instruction_line.find(' ');
        std::string mnemonic = (firstSpace == std::string::npos) ? instruction_line : instruction_line.substr(0, firstSpace);
        std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::tolower);
        if (mnemonic == "ret" || mnemonic == "iret" || mnemonic == "iretd" || mnemonic == "iretq") return COLOR_RET_INSTR;
        if (mnemonic == "jmp" || (mnemonic.length() > 1 && mnemonic[0] == 'j' && mnemonic != "jecxz")) return COLOR_JMP_INSTR;
        if (mnemonic == "call") {
            if (instruction_line.find('!') != std::string::npos) return COLOR_CALL_INSTR;
            return COLOR_CALL_INSTR;
        }
        return COLOR_DEFAULT_INSTR;
    }
    void DrawGraphView() {
        ImGui::BeginChild("GraphCanvas", ImVec2(0, 0), true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        ImGuiIO& io = ImGui::GetIO();
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
        ImVec2 canvas_size = ImGui::GetContentRegionAvail();

        bool is_window_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
        bool is_window_hovered = ImGui::IsWindowHovered();
        if (is_window_hovered && io.KeyCtrl && io.MouseWheel != 0.0f) {
            ImVec2 mouse_pos_screen = io.MousePos;
            ImVec2 mouse_pos_world_before = ScreenToWorld(mouse_pos_screen, current_view_offset, current_zoom);
            float zoom_delta = io.MouseWheel * 0.1f;
            float new_zoom = current_zoom * (1.0f + zoom_delta);
            new_zoom = std::max(0.05f, std::min(new_zoom, 5.0f));
            current_view_offset = mouse_pos_screen - (mouse_pos_world_before * new_zoom);
            current_zoom = new_zoom;
        }
        bool can_start_pan = is_window_hovered && !is_dragging_node;
        bool pan_requested = ImGui::IsMouseDragging(ImGuiMouseButton_Middle) || (io.KeyCtrl && ImGui::IsMouseDragging(ImGuiMouseButton_Left));
        if (can_start_pan && pan_requested && !is_panning) {
            is_panning = true;
            pan_start_mouse_pos = io.MousePos;
            pan_start_view_offset = current_view_offset;
        }
        if (is_window_hovered && !is_panning && !is_dragging_node && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            ImVec2 mouse_pos_screen = io.MousePos;
            ImVec2 mouse_pos_world = ScreenToWorld(mouse_pos_screen, current_view_offset, current_zoom);
            bool node_hit = false;
            for (auto it = node_positions.rbegin(); it != node_positions.rend(); ++it) {
                const std::string& name = it->first;
                if (!node_sizes.count(name)) continue;

                ImVec2 node_pos_world = it->second;
                ImVec2 node_size_world = node_sizes.at(name);
                ImVec2 node_tl_world = node_pos_world - node_size_world / 2.0f;
                ImVec2 node_br_world = node_pos_world + node_size_world / 2.0f;
                if (mouse_pos_world.x >= node_tl_world.x && mouse_pos_world.x <= node_br_world.x &&
                    mouse_pos_world.y >= node_tl_world.y && mouse_pos_world.y <= node_br_world.y)
                {
                    is_dragging_node = true;
                    dragged_node_id = name;
                    drag_node_start_offset_world = mouse_pos_world - node_pos_world;
                    node_hit = true;
                    break;
                }
            }
        }
        if (is_panning && (ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f) || (io.KeyCtrl && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)))) {
            if (is_window_focused || ImGui::IsWindowHovered()) {
                ImVec2 mouse_delta = io.MousePos - pan_start_mouse_pos;
                current_view_offset = pan_start_view_offset + mouse_delta;
            }
            else {
                is_panning = false;
            }
        }
        else if (is_panning && !(ImGui::IsMouseDown(ImGuiMouseButton_Middle) || (io.KeyCtrl && ImGui::IsMouseDown(ImGuiMouseButton_Left)))) {
            is_panning = false;
        }
        if (is_dragging_node && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) {
            ImVec2 mouse_pos_screen = io.MousePos;
            ImVec2 mouse_pos_world = ScreenToWorld(mouse_pos_screen, current_view_offset, current_zoom);
            ImVec2 new_node_center_world = mouse_pos_world - drag_node_start_offset_world;
            node_positions[dragged_node_id] = new_node_center_world;
        }
        else if (is_dragging_node && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            is_dragging_node = false;
            dragged_node_id = "";
        }
        draw_list->PushClipRect(canvas_pos, canvas_pos + canvas_size, true);
        const float min_len_sq_arrow = 1e-8f;
        const ImU32 edge_color = IM_COL32(200, 200, 200, 200);
        const ImU32 arrow_color = IM_COL32(200, 200, 200, 255);

        for (const auto& e : edges) {
            std::string from = e.first;
            std::string to = e.second;
            auto edge_key = std::make_pair(from, to);
            if (edge_curves.count(edge_key) && node_positions.count(from) && node_positions.count(to)) {
                const auto& curves = edge_curves.at(edge_key);
                if (curves.empty()) continue;

                ImVec2 final_p_screen = { 0,0 };
                ImVec2 penultimate_p_screen = { 0,0 };
                for (size_t i = 0; i < curves.size(); ++i) {
                    const auto& curve_data = curves[i];
                    ImVec2 p0 = WorldToScreen(curve_data[0], current_view_offset, current_zoom);
                    ImVec2 p1 = WorldToScreen(curve_data[1], current_view_offset, current_zoom);
                    ImVec2 p2 = WorldToScreen(curve_data[2], current_view_offset, current_zoom);
                    ImVec2 p3 = WorldToScreen(curve_data[3], current_view_offset, current_zoom);
                    draw_list->AddBezierCubic(p0, p1, p2, p3, edge_color, 1.5f * std::min(1.0f, current_zoom));
                    if (i == curves.size() - 1) {
                        final_p_screen = p3;
                        ImVec2 dir_seg = p3 - p2;
                        if (dir_seg.x * dir_seg.x + dir_seg.y * dir_seg.y > min_len_sq_arrow) {
                            penultimate_p_screen = p2;
                        }
                        else if (!curves.empty()) {
                            penultimate_p_screen = WorldToScreen(curves[0][0], current_view_offset, current_zoom);
                        }
                        else {
                            penultimate_p_screen = p3 - ImVec2(0, 1);
                        }
                    }
                }
                ImVec2 dir_screen = final_p_screen - penultimate_p_screen;
                if (dir_screen.x * dir_screen.x + dir_screen.y * dir_screen.y > min_len_sq_arrow * current_zoom * current_zoom) {
                    DrawArrow(draw_list, final_p_screen, dir_screen, arrow_color, 7.0f * std::min(1.0f, current_zoom));
                }
            }
        }
        ImFont* font_to_use = (g_CodeFont != nullptr) ? g_CodeFont : ImGui::GetFont();
        float default_font_size = font_to_use->FontSize;
        if (default_font_size < 1.0f) default_font_size = 13.0f;
        float default_line_height = ImGui::GetTextLineHeightWithSpacing();
        if (default_line_height < 1.0f) default_line_height = 15.0f;

        const ImU32 node_bg_color = IM_COL32(45, 45, 50, 230);
        const ImU32 node_border_color = IM_COL32(150, 150, 160, 200);
        const ImU32 title_color = IM_COL32(230, 230, 180, 255);
        const float text_padding = 5.0f;
        const float min_font_size_pixels = 6.0f;
        const float max_font_size_multiplier = 2.0f;

        for (const auto& p : node_positions) {
            std::string name = p.first;
            if (node_sizes.count(name) && block_titles.count(name) && block_instructions.count(name)) {
                ImVec2 node_pos_world = p.second;
                ImVec2 node_size_world = node_sizes.at(name);
                ImVec2 node_pos_screen = WorldToScreen(node_pos_world, current_view_offset, current_zoom);
                ImVec2 node_size_screen = node_size_world * current_zoom;
                ImVec2 tl = node_pos_screen - node_size_screen / 2.0f;
                ImVec2 br = node_pos_screen + node_size_screen / 2.0f;
                if (br.x < canvas_pos.x || tl.x > canvas_pos.x + canvas_size.x ||
                    br.y < canvas_pos.y || tl.y > canvas_pos.y + canvas_size.y) {
                    continue;
                }
                float node_rounding = 4.0f * std::min(1.0f, current_zoom);
                float border_thickness = 1.0f * std::min(1.0f, current_zoom);
                draw_list->AddRectFilled(tl, br, node_bg_color, node_rounding);
                draw_list->AddRect(tl, br, node_border_color, node_rounding, 0, border_thickness);
                float scaled_padding = text_padding * std::min(1.0f, current_zoom);
                ImVec2 text_area_tl = tl + ImVec2(scaled_padding, scaled_padding);
                ImVec2 text_area_br = br - ImVec2(scaled_padding, scaled_padding);
                ImVec2 text_area_size = text_area_br - text_area_tl;
                if (text_area_size.x > 1 && text_area_size.y > 1) {
                    const auto& instructions = block_instructions.at(name);
                    const std::string& title = block_titles.at(name);
                    int num_lines = 1 + (instructions.empty() ? 0 : 1) + static_cast<int>(instructions.size());
                    if (num_lines <= 0) continue;
                    float font_size_based_on_height = (default_line_height > 1e-5f && num_lines > 0)
                        ? (text_area_size.y / num_lines) * (default_font_size / default_line_height)
                        : default_font_size;
                    float font_size_based_on_zoom = default_font_size * current_zoom;
                    float target_font_size = std::min(font_size_based_on_height, font_size_based_on_zoom);
                    float final_scaled_font_size = ImClamp(target_font_size, min_font_size_pixels, default_font_size * max_font_size_multiplier);
                    if (final_scaled_font_size >= min_font_size_pixels) {
                        ImGui::PushFont(font_to_use);
                        float font_scale = final_scaled_font_size / font_to_use->FontSize;
                        float final_scaled_line_height = ImGui::GetTextLineHeightWithSpacing() * font_scale;
                        ImGui::PopFont();
                        if (final_scaled_line_height < 1.0f) final_scaled_line_height = 1.0f;
                        float separator_height = std::max(1.0f, 1.0f * std::min(1.0f, current_zoom));
                        float actual_text_block_height = (1 * final_scaled_line_height)
                            + (instructions.empty() ? 0 : separator_height)
                            + (instructions.size() * final_scaled_line_height);
                        float text_area_center_y = text_area_tl.y + text_area_size.y * 0.5f;
                        float start_y = text_area_center_y - actual_text_block_height * 0.5f;
                        start_y = std::max(start_y, text_area_tl.y);
                        ImVec2 current_pos = ImVec2(text_area_tl.x, start_y);
                        draw_list->PushClipRect(text_area_tl, text_area_br, true);
                        if (current_pos.y < text_area_br.y) {
                            draw_list->AddText(font_to_use, final_scaled_font_size, current_pos, title_color, title.c_str());
                            current_pos.y += final_scaled_line_height;
                        }
                        if (!instructions.empty() && current_pos.y < text_area_br.y - separator_height) {
                            draw_list->AddLine(ImVec2(current_pos.x, current_pos.y), ImVec2(text_area_br.x, current_pos.y), IM_COL32(80, 80, 80, 150), border_thickness);
                            current_pos.y += separator_height;
                        }
                        for (const auto& instPair : instructions) {
                            if (current_pos.y < text_area_br.y - 1.0f) {
                                ImU32 current_text_color = GetInstructionColor(instPair.second);
                                std::string text_to_draw;
                                if (App::State::show_instruction_addresses) {
                                    std::stringstream ss_addr;
                                    ss_addr << "0x" << std::hex << std::setw(16) << std::setfill('0') << instPair.first << "  ";
                                    text_to_draw += ss_addr.str();
                                }
                                text_to_draw += instPair.second;
                                draw_list->AddText(font_to_use, final_scaled_font_size, current_pos, current_text_color, text_to_draw.c_str());
                                current_pos.y += final_scaled_line_height;
                            }
                            else {
                                break;
                            }
                        }
                        draw_list->PopClipRect();
                    }
                }
            }
        }
        draw_list->PopClipRect();
        ImGui::EndChild();
    }
    void DrawXrefsWindow() {
        if (!show_xrefs_window || xrefs_target_function_address == 0) {
            return;
        }
        std::string target_name = "Unknown Function";
        if (function_address_to_name.count(xrefs_target_function_address)) {
            target_name = function_address_to_name[xrefs_target_function_address];
        }
        else if (!xrefs_target_function_name.empty()) {
            target_name = xrefs_target_function_name;
        }

        std::string window_title = "XREFS - " + target_name;
        ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_Once);
        if (ImGui::Begin(window_title.c_str(), &show_xrefs_window)) {
            ImGui::Text("Callers to function: %s (0x%llX)", target_name.c_str(), (unsigned long long)xrefs_target_function_address);
            ImGui::Separator();
            if (xrefs_data.count(xrefs_target_function_address)) {
                const auto& callers = xrefs_data.at(xrefs_target_function_address);

                if (callers.empty()) {
                    ImGui::Text("No known callers found within this module.");
                }
                else {
                    if (ImGui::BeginChild("XrefsList", ImVec2(0, 0), true)) {
                        std::vector<std::pair<uintptr_t, int>> sorted_callers;
                        for (const auto& pair : callers) {
                            sorted_callers.push_back(pair);
                        }
                        std::sort(sorted_callers.begin(), sorted_callers.end(), [&](const auto& a, const auto& b) {
                            return a.first < b.first;
                            });
                        for (const auto& pair : sorted_callers) {
                            uintptr_t caller_addr = pair.first;
                            int call_count = pair.second;
                            std::string caller_name = "Unknown Caller";
                            if (function_address_to_name.count(caller_addr)) {
                                caller_name = function_address_to_name[caller_addr];
                            }
                            std::stringstream ss_label;
                            ss_label << caller_name << " (0x" << std::hex << caller_addr << ") - [" << std::dec << call_count << " calls]";
                            std::string label = ss_label.str();
                            if (ImGui::Selectable(label.c_str())) {
                                bool found_caller_info = false;
                                for (auto& f : functions) {
                                    if (f.address == caller_addr) {
                                        selected_function = f;
                                        Analysis::LoadFunctionInstructions(selected_function);
                                        layout_function_address = 0;
                                        show_graph_window = false;
                                        found_caller_info = true;
                                        break;
                                    }
                                }
                                if (!found_caller_info) {
                                    std::cerr << "Erro: Não foi possível encontrar FunctionInfo para o chamador: " << caller_name << std::endl;
                                }
                            }
                        }
                    }
                    ImGui::EndChild();
                }
            }
            else {
                ImGui::Text("No cross-reference data available for this function.");
                if (!analysis_results_valid && !is_analyzing) {
                    ImGui::TextColored(ImVec4(1.f, 1.f, 0.f, 1.f), "Analysis might be incomplete or failed.");
                }
            }
        }
        ImGui::End();
        if (!show_xrefs_window) {
            xrefs_target_function_address = 0;
            xrefs_target_function_name = "";
        }
    }
    void Draw() {
        ImGui::SetNextWindowSize(ImVec2(1000, 600), ImGuiCond_Once);
        ImGui::Begin("Disassembler");
        if (is_analyzing) ImGui::BeginDisabled();
        if (ImGui::Button("List Processes")) {
            list_processes_window_open = true;
            needs_process_refresh = true;
            process_filter = "";
            if (process_handle) { CloseHandle(process_handle); process_handle = nullptr; }
            selected_pid = 0;
            selected_module = nullptr;
            functions.clear();
            function_address_to_name.clear();
            xrefs_data.clear();
            resolved_iat_targets.clear();
            selected_function = {};
            analysis_results_valid = false;
            is_analyzing = false;
            show_xrefs_window = false;
            show_modules_window = false;
            show_graph_window = false;
        }
        if (is_analyzing) ImGui::EndDisabled();
        if (list_processes_window_open) {
            ImGui::SetNextWindowSize(ImVec2(400, 500), ImGuiCond_Once);
            ImGui::Begin("Processes", &list_processes_window_open);

            if (ImGui::Button("Refresh Processes")) {
                needs_process_refresh = true;
            }
            ImGui::SameLine();
            static char proc_filter_buf[128] = "";
            if (process_filter != proc_filter_buf && !ImGui::IsItemActive()) {
                strncpy(proc_filter_buf, process_filter.c_str(), sizeof(proc_filter_buf) - 1);
                proc_filter_buf[sizeof(proc_filter_buf) - 1] = '\0';
            }
            if (ImGui::InputText("Filter (Name/PID)", proc_filter_buf, sizeof(proc_filter_buf))) {
                process_filter = proc_filter_buf;
            }
            ImGui::Separator();
            Utils::Process::RefreshProcessList();
            if (ImGui::BeginChild("ProcessList", ImVec2(0, 0), true)) {
                for (const auto& p : cached_processes) {
                    DWORD pid = p.first;
                    const std::string& name = p.second;
                    std::string pid_str = std::to_string(pid);
                    std::string display_name = name + " (" + pid_str + ")";
                    if (process_filter.empty() ||
                        Utils::ContainsCaseInsensitive(name, process_filter) ||
                        Utils::ContainsCaseInsensitive(pid_str, process_filter))
                    {
                        if (ImGui::Button(display_name.c_str())) {
                            if (process_handle) CloseHandle(process_handle);

                            selected_pid = pid;
                            process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION, FALSE, pid);

                            if (process_handle) {
                                show_modules_window = true;
                                needs_module_refresh = true;
                                module_filter = "";
                                list_processes_window_open = false;
                                selected_module = nullptr;
                                module_base = 0;
                                module_size = 0;
                                functions.clear();
                                function_address_to_name.clear();
                                resolved_iat_targets.clear();
                                selected_function = {};
                                layout_function_address = 0;
                                show_graph_window = false;
                                node_positions.clear();
                                node_sizes.clear();
                                edges.clear();
                                edge_curves.clear();
                                block_instructions.clear();
                                block_titles.clear();
                                xrefs_data.clear();
                                is_analyzing = false;
                                analysis_results_valid = false;
                                show_xrefs_window = false;

                            }
                            else {
                                selected_pid = 0;
                                std::cerr << "Failed to open process " << pid << ". Error code: " << GetLastError() << std::endl;
                            }
                        }
                    }
                }
            }
            ImGui::EndChild();
            ImGui::End();
        }
        if (selected_pid != 0 && process_handle != nullptr) {
            ImGui::Spacing(); ImGui::Separator();
            ImGui::Text("Process: %s (%u)", Utils::Process::GetProcessNameFromCache(selected_pid).c_str(), selected_pid);
            if (ImGui::Button("Select Module")) {
                if (!is_analyzing) {
                    show_modules_window = true;
                    needs_module_refresh = true;
                    module_filter = "";
                }
                else {
                }
            }

            ImGui::SameLine();
            if (ImGui::Button(show_function_list_column ? "Hide Functions" : "Show Functions")) {
                show_function_list_column = !show_function_list_column;
            }
            if (show_modules_window) {
                ImGui::SetNextWindowSize(ImVec2(600, 400), ImGuiCond_Once);
                ImGui::Begin("Modules", &show_modules_window);

                if (ImGui::Button("Refresh Modules")) {
                    needs_module_refresh = true;
                }
                ImGui::SameLine();
                static char mod_filter_buf[256] = "";
                if (module_filter != mod_filter_buf && !ImGui::IsItemActive()) {
                    strncpy(mod_filter_buf, module_filter.c_str(), sizeof(mod_filter_buf) - 1);
                    mod_filter_buf[sizeof(mod_filter_buf) - 1] = '\0';
                }
                if (ImGui::InputText("Filter Modules", mod_filter_buf, sizeof(mod_filter_buf))) {
                    module_filter = mod_filter_buf;
                }
                ImGui::Separator();
                Utils::Module::RefreshModuleList(process_handle);
                if (ImGui::BeginChild("ModuleList", ImVec2(0, 0), true)) {
                    for (const auto& mod_tuple : cached_modules) {
                        HMODULE m = std::get<0>(mod_tuple);
                        const std::string& module_name = std::get<1>(mod_tuple);
                        uintptr_t mod_base = std::get<2>(mod_tuple);
                        size_t mod_size = std::get<3>(mod_tuple);
                        std::stringstream ss_mod;
                        ss_mod << module_name << " (Base: 0x" << std::hex << mod_base << ", Size: 0x" << mod_size << ")";
                        std::string display_name = ss_mod.str();
                        if (module_filter.empty() || Utils::ContainsCaseInsensitive(module_name, module_filter) || Utils::ContainsCaseInsensitive(display_name, module_filter)) {
                            bool is_currently_selected = (selected_module == m);
                            if (is_analyzing) {
                                ImGui::BeginDisabled();
                            }
                            if(ImGui::Button(display_name.c_str())) {
                                if (!is_analyzing) {
                                    selected_module = m;
                                    module_base = mod_base;
                                    module_size = mod_size;
                                    show_modules_window = false;
                                    is_analyzing = true;
                                    analysis_results_valid = false;
                                    analysis_status_message = "Starting analysis...";
                                    show_xrefs_window = false;
                                    show_graph_window = false;
                                    selected_function = {};
                                    function_filter = "";
                                    xrefs_data.clear();
                                    functions.clear();
                                    function_address_to_name.clear();
                                    resolved_iat_targets.clear();
                                    std::thread analysisThread(Analysis::PerformFullAnalysis, process_handle, module_base, module_size);
                                    analysisThread.detach();

                                }
                            }

                            if (is_analyzing) {
                                ImGui::EndDisabled();
                            }
                        }
                    }
                }
                ImGui::EndChild();
                ImGui::End();
            }
            if (selected_module != nullptr) {
                ImGui::Spacing(); ImGui::Separator();
                std::string current_module_name = "Unknown";
                for (const auto& mt : cached_modules) { if (std::get<0>(mt) == selected_module) { current_module_name = std::get<1>(mt); break; } }
                ImGui::Text("Module: %s (Base: 0x%llX, Size: 0x%zX)", current_module_name.c_str(), (unsigned long long)module_base, module_size);
                if (is_analyzing) {
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Analyzing... %s", analysis_status_message.c_str());
                    ImGui::Separator();
                }
                else if (analysis_results_valid)
                {
                    bool use_columns = show_function_list_column;
                    if (use_columns) {
                        ImGui::Columns(2, "MainSplit", true);
                        ImGui::SetColumnWidth(0, 300.0f);
                        ImGui::BeginChild("FuncPanel", ImVec2(0, 0), true);
                        static char func_filter_buf[128] = "";
                        if (function_filter != func_filter_buf && !ImGui::IsItemActive()) {
                            strncpy(func_filter_buf, function_filter.c_str(), sizeof(func_filter_buf) - 1);
                            func_filter_buf[sizeof(func_filter_buf) - 1] = '\0';
                        }
                        if (ImGui::InputText("Filter Functions", func_filter_buf, sizeof(func_filter_buf))) {
                            function_filter = func_filter_buf;
                        }
                        ImGui::Separator();
                        if (functions.empty()) {
                            ImGui::Text("No functions found in this module.");
                        }
                        else {
                            if (ImGui::BeginChild("FunctionListScroll", ImVec2(0, 0), false)) {
                                for (auto& f : functions) {
                                    if (function_filter.empty() || Utils::ContainsCaseInsensitive(f.name, function_filter))
                                    {
                                        if (ImGui::Selectable(f.name.c_str(), f.address == selected_function.address)) {
                                            if (f.address != selected_function.address) {
                                                selected_function = f;
                                                Analysis::LoadFunctionInstructions(selected_function);
                                                layout_function_address = 0;
                                                show_graph_window = false;
                                            }
                                        }
                                    }
                                }
                            }
                            ImGui::EndChild();
                        }
                        ImGui::EndChild();
                        ImGui::NextColumn();
                    }
                    ImGui::BeginChild("InstrGraphPanel", ImVec2(0, 0), true);
                    if (selected_function.address != 0) {
                        ImGui::Checkbox("Show Addresses", &show_instruction_addresses); ImGui::SameLine();

                        if (ImGui::Button("Show Instructions")) {
                            show_graph_window = false;
                        }
                        ImGui::SameLine();

                        if (ImGui::Button("Copy Instructions")) {
                            if (!selected_function.instructions_with_addr.empty()) {
                                std::stringstream ss_copy;
                                for (const auto& instrPair : selected_function.instructions_with_addr) {
                                    const uintptr_t& addr = instrPair.first;
                                    const std::string& line = instrPair.second;
                                    bool is_label = !line.empty() && line.back() == ':';
                                    if (show_instruction_addresses && !is_label) {
                                        std::stringstream ss_addr;
                                        ss_addr << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr << "  ";
                                        ss_copy << ss_addr.str();
                                    }
                                    else if (show_instruction_addresses && is_label) {
                                        ss_copy << "                    ";
                                    }
                                    ss_copy << line << "\n";
                                }
                                ImGui::SetClipboardText(ss_copy.str().c_str());
                            }
                        }
                        ImGui::SameLine();
                        if (ImGui::Button("Generate XREFS")) {
                            if (selected_function.address != 0) {
                                xrefs_target_function_address = selected_function.address;
                                xrefs_target_function_name = selected_function.name;
                                show_xrefs_window = true;
                            }
                        }
                        ImGui::SameLine();
                        if (ImGui::Button("Generate Graph View")) {
                            show_graph_window = true;
                            bool force_recalc = show_instruction_addresses != (bool)App::State::node_positions.empty();
                            if (layout_function_address != selected_function.address) {
                                auto blocks = Analysis::BuildBlocks(selected_function);
                                if (!blocks.empty()) {
                                    if (Analysis::CalculateLayout(blocks)) {
                                        layout_function_address = selected_function.address;
                                        float min_x = std::numeric_limits<float>::max(), min_y = std::numeric_limits<float>::max();
                                        float max_x = std::numeric_limits<float>::min(), max_y = std::numeric_limits<float>::min();
                                        bool has_pos = !node_positions.empty();
                                        if (has_pos) {
                                            for (const auto& p : node_positions) {
                                                if (node_sizes.count(p.first)) {
                                                    ImVec2 pos = p.second; ImVec2 size = node_sizes.at(p.first);
                                                    min_x = std::min(min_x, pos.x - size.x / 2.0f); min_y = std::min(min_y, pos.y - size.y / 2.0f);
                                                    max_x = std::max(max_x, pos.x + size.x / 2.0f); max_y = std::max(max_y, pos.y + size.y / 2.0f);
                                                }
                                            }
                                        }
                                        ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
                                        ImVec2 canvas_size = ImGui::GetContentRegionAvail();
                                        ImVec2 canvas_size_now = ImGui::GetContentRegionAvail();
                                        if (has_pos && (max_x > min_x || max_y > min_y)) {
                                            ImVec2 graph_center_world = ImVec2((min_x + max_x) / 2.0f, (min_y + max_y) / 2.0f);
                                            float graph_width_world = max_x - min_x; float graph_height_world = max_y - min_y;
                                            ImVec2 canvas_size_now = ImGui::GetContentRegionAvail();
                                            if (canvas_size_now.x <= 0) canvas_size_now.x = 600;
                                            if (canvas_size_now.y <= 0) canvas_size_now.y = 400;
                                            float zoom_x = (canvas_size_now.x > 20 && graph_width_world > 1) ? (canvas_size_now.x * 0.9f) / graph_width_world : 1.0f;
                                            float zoom_y = (canvas_size_now.y > 20 && graph_height_world > 1) ? (canvas_size_now.y * 0.9f) / graph_height_world : 1.0f;
                                            current_zoom = std::min({ zoom_x, zoom_y, 1.5f });
                                            current_zoom = std::max(0.05f, current_zoom);
                                            ImVec2 canvas_center_screen = canvas_pos + canvas_size_now * 0.5f;
                                            initial_centering_offset = canvas_center_screen - (graph_center_world * current_zoom);
                                        }
                                        else {
                                            initial_centering_offset = canvas_pos + canvas_size_now * 0.5f;
                                            current_zoom = 1.0f;
                                        }
                                        current_view_offset = initial_centering_offset;
                                        is_dragging_node = false;
                                        is_panning = false;
                                    }
                                    else {
                                        show_graph_window = false;
                                        layout_function_address = 0;
                                    }
                                }
                                else {
                                    show_graph_window = false;
                                    layout_function_address = 0;
                                }
                            }
                            else if (!node_positions.empty()) {
                                current_view_offset = initial_centering_offset;
                                is_dragging_node = false;
                                is_panning = false;
                            }
                        }

                        ImGui::Separator();
                        if (!show_graph_window) {
                            ImGui::Text("Instructions:");
                            if (selected_function.instructions_with_addr.empty()) {
                                ImGui::Text("Instructions not loaded or function is empty.");
                            }
                            else {
                                ImGui::PushFont(g_CodeFont ? g_CodeFont : ImGui::GetFont());
                                if (ImGui::BeginChild("InstructionScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar)) {
                                    ImGuiListClipper clipper;
                                    clipper.Begin(selected_function.instructions_with_addr.size());
                                    while (clipper.Step()) {
                                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                                            const auto& instrPair = selected_function.instructions_with_addr[i];
                                            uintptr_t addr = instrPair.first;
                                            const std::string& line = instrPair.second;
                                            bool is_label = !line.empty() && line.back() == ':';
                                            if (show_instruction_addresses) {
                                                if (!is_label) {
                                                    std::stringstream ss_addr;
                                                    ss_addr << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr;
                                                    ImGui::TextDisabled("%s", ss_addr.str().c_str());
                                                    ImGui::SameLine();
                                                }
                                                else {
                                                    ImGui::TextUnformatted("                    ");
                                                    ImGui::SameLine();
                                                }
                                            }
                                            if (is_label) {
                                                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(COLOR_LABEL), "%s", line.c_str());
                                            }
                                            else {
                                                ImU32 color = GetInstructionColor(line);
                                                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(color), "%s", line.c_str());
                                            }
                                        }
                                    }
                                    clipper.End();
                                }
                                ImGui::EndChild();
                                ImGui::PopFont();
                            }
                        }
                        else {
                            ImGui::Text("Graph View: (Ctrl+Scroll = Zoom, Ctrl+Drag / Middle Mouse = Pan)");
                            DrawGraphView();
                        }

                    }
                    else {
                        ImGui::Text("Select a function from the list.");
                    }
                    ImGui::EndChild();
                    if (use_columns) {
                        ImGui::Columns(1);
                    }

                }
                else if (!is_analyzing && selected_module != nullptr) {
                    ImGui::TextColored(ImVec4(1.f, 1.f, 0.f, 1.f), "Analysis complete, but no valid results found or analysis failed for this module.");
                    ImGui::TextColored(ImVec4(1.f, 1.f, 0.f, 1.f), "Status: %s", analysis_status_message.c_str());
                }

            }
            else if (!show_modules_window) {
                ImGui::Text("Select a module using 'Select Module'.");
            }
        }
        else if (selected_pid != 0 && process_handle == nullptr) {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Error: Failed to open process %u. Elevated rights might be required or process closed.", selected_pid);
        }
        else if (!list_processes_window_open) {
            ImGui::Text("Select a process using 'List Processes'.");
        }

        ImGui::End();
        DrawXrefsWindow();

    }

}