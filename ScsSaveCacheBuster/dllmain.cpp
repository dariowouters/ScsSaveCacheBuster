#define WIN32_LEAN_AND_MEAN

#include "Windows.h"
#include "memory.h"
#include "prism.h"
#include "MinHook.h"
#include "scs_sdk/scssdk_telemetry.h"

uintptr_t g_game_base;
uint32_t g_module_size = 0;
scs_log_t g_scs_log = nullptr;

uint64_t load_unit_tree_economy_u_address = 0;
prism::load_unit_tree_economy_u_fn* original_load_unit_tree_economy_u_fn = nullptr;
prism::fs_remove_from_cache_fn* fs_remove_from_cache = nullptr;

bool g_installed = false;

uint64_t detoured_load_unit_tree_economy_u_(const uint64_t a1, prism::string& path, const uint64_t a3, const uint64_t a4)
{
    fs_remove_from_cache(path, 1);
    return original_load_unit_tree_economy_u_fn(a1, path, a3, a4);
}

bool install()
{
    const auto load_unit_tree_economy_u_call_address = pattern::scan("48 8d 8d ? ? ? ? e8 ? ? ? ? 4c 8b bd ? ? ? ? 48 8b d0 49 81 c7", g_game_base, g_module_size);

    if (load_unit_tree_economy_u_call_address == 0)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find pattern for 'load_unit_tree<economy_u>'");
        return false;
    }

    load_unit_tree_economy_u_address = load_unit_tree_economy_u_call_address + 8 + *reinterpret_cast<int32_t*>(load_unit_tree_economy_u_call_address + 8) + 4;

    const auto fs_remove_from_cache_call_address = pattern::scan(
        "ba ? ? ? ? 48 8b 59 ? 48 8d 4b ? e8 ? ? ? ? b9 ? ? ? ? e8",
        g_game_base,
        g_module_size
    );

    if (fs_remove_from_cache_call_address == NULL)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find pattern for 'fs_remove_from_cache'");
        return false;
    }

    fs_remove_from_cache = reinterpret_cast<prism::fs_remove_from_cache_fn*>(fs_remove_from_cache_call_address + *reinterpret_cast<int32_t*>(fs_remove_from_cache_call_address + 14) + 14 + 4);

    if (MH_CreateHook(reinterpret_cast<LPVOID>(load_unit_tree_economy_u_address),
                      &detoured_load_unit_tree_economy_u_,
                      reinterpret_cast<LPVOID*>(&original_load_unit_tree_economy_u_fn)) != MH_OK)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not create 'load_unit_tree<economy_u>' hook");
        return false;
    }

    if (MH_EnableHook(reinterpret_cast<LPVOID>(load_unit_tree_economy_u_address)) != MH_OK)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not enable 'load_unit_tree<economy_u>' hook");
        return false;
    }
    g_installed = true;
    return true;
}

void uninstall()
{
    if (!g_installed) return;
    if (MH_DisableHook(reinterpret_cast<LPVOID>(load_unit_tree_economy_u_address)) != MH_OK)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not disable 'load_unit_tree<economy_u>' hook");
        return;
    }

    if (MH_RemoveHook(reinterpret_cast<LPVOID>(load_unit_tree_economy_u_address)) != MH_OK)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not remove 'load_unit_tree<economy_u>' hook");
        return;
    }
    g_installed = false;
}

SCSAPI_RESULT scs_telemetry_init(const scs_u32_t version, const scs_telemetry_init_params_t* const params)
{
    // We currently support only one version.
    if (version != SCS_TELEMETRY_VERSION_1_01)
    {
        return SCS_RESULT_unsupported;
    }

    const auto version_params = reinterpret_cast<const scs_telemetry_init_params_v101_t*>(params);
    g_scs_log = version_params->common.log;

    const auto res = MH_Initialize();
    if (res != MH_OK)
    {
        std::stringstream ss;
        ss << "[ScsSaveCacheBuster] Could not initialize MinHook: " << std::hex << res;
        g_scs_log(SCS_LOG_TYPE_message, ss.str().c_str());
    }

    if (!install())
    {
        return SCS_RESULT_generic_error;
    }

    g_scs_log(SCS_LOG_TYPE_message, "[ScsSaveCacheBuster] Plugin Loaded");

    return SCS_RESULT_ok;
}

/**
 * @brief Telemetry API deinitialization function.
 *
 * See scssdk_telemetry.h
 */
SCSAPI_VOID scs_telemetry_shutdown(void)
{
    uninstall();
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_game_base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
        const auto header = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_game_base);
        const auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const uint8_t*>(header) + header->e_lfanew);
        g_module_size = nt_header->OptionalHeader.SizeOfImage;
    }

    return TRUE;
}
