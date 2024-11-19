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
prism::fs_get_cached_entry_fn* fs_get_cached_entry = nullptr;
prism::cache_entry_t_destructor_fn* cache_entry_t_destructor = nullptr;
uint64_t fs_cached_entries_mutex = 0;

bool g_installed = false;

uint64_t detoured_load_unit_tree_economy_u_(const uint64_t a1, prism::string& path, const uint64_t a3, const uint64_t a4)
{
    AcquireSRWLockExclusive(reinterpret_cast<PSRWLOCK>(fs_cached_entries_mutex));

    const auto cache_entry = fs_get_cached_entry(path, 1);

    ReleaseSRWLockExclusive(reinterpret_cast<PSRWLOCK>(fs_cached_entries_mutex));

    if (cache_entry)
    {
        cache_entry->next_entry->prev_entry = cache_entry->prev_entry;
        cache_entry->prev_entry->next_entry = cache_entry->next_entry;
        cache_entry_t_destructor(cache_entry);
        g_scs_log(SCS_LOG_TYPE_message, "[ScsSaveCacheBuster] Cleared Save Cache");
    }

    return original_load_unit_tree_economy_u_fn(a1, path, a3, a4);
}

bool install()
{
    load_unit_tree_economy_u_address = pattern::scan("48 89 5c 24 10 48 89 74 24 18 55 57 41 54 41 56 41 57 48 8b ec 48 81 ec 80 00 00 00 49 8b f9 45 8b f0 48 8b f1 41 b9 01 00 00 00", g_game_base, g_module_size);

    if (load_unit_tree_economy_u_address == 0)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find address for 'load_unit_tree<economy_u>'");
        return false;
    }

    const auto offsets = pattern::scan(
        "e8 ? ? ? ? 48 8b d8 48 85 c0 74 ? 48 8b 10 48 8b 48 08 48 89 4a 08 48 8b 50 08 48 8b 08 33 c0 48 89 0a 48 89 03 48 89 43 08 48 8d 0d ? ? ? ? ff 15 ? ? ? ? 48 85 db 74 ? 48 8b cb e8",
        g_game_base,
        g_module_size
    );

    if (offsets == NULL)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find pattern for 'fs_get_cached_entry | fs cache mutex | cache_entry_t::destructor'");
        return false;
    }

    fs_get_cached_entry = reinterpret_cast<prism::fs_get_cached_entry_fn*>(offsets + *reinterpret_cast<int32_t*>(offsets + 1) + 1 + 4);
    fs_cached_entries_mutex = offsets + *reinterpret_cast<int32_t*>(offsets + 46) + 46 + 4;
    cache_entry_t_destructor = reinterpret_cast<prism::cache_entry_t_destructor_fn*>(offsets + *reinterpret_cast<int32_t*>(offsets + 65) + 65 + 4);

    if (fs_get_cached_entry == nullptr)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find address for 'fs_get_cached_entry'");
        return false;
    }

    if (fs_cached_entries_mutex == 0)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find address for fs cache mutex");
        return false;
    }

    if (cache_entry_t_destructor == nullptr)
    {
        g_scs_log(SCS_LOG_TYPE_error, "[ScsSaveCacheBuster] Could not find address for 'cache_entry_t::destructor'");
        return false;
    }

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
