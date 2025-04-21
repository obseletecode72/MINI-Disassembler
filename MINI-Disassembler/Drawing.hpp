#define IMGUI_DEFINE_MATH_OPERATORS
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <d3d11.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <limits>
#include <array>
#include <functional>
#include <iostream>
#include <cctype>
#include <tuple>
#include <winnt.h>

#include "Zydis/Zydis.h"
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx11.h"
#include "ImGui/imgui_impl_win32.h"
#include "ImGui/imgui_internal.h"
#include <graphviz/cgraph.h>
#include <graphviz/gvc.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "gvc.lib")
#pragma comment(lib, "cgraph.lib")
#pragma comment(lib, "pathplan.lib")
#pragma comment(lib, "cdt.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

#define COLOR_RET_INSTR IM_COL32(255, 192, 203, 255)
#define COLOR_JMP_INSTR IM_COL32(173, 216, 230, 255)
#define COLOR_CALL_INSTR IM_COL32(255, 255, 0, 255)
#define COLOR_DEFAULT_INSTR IM_COL32(210, 210, 210, 255)
#define COLOR_LABEL IM_COL32(180, 180, 180, 255)