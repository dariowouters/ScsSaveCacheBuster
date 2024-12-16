#pragma once

namespace prism
{
    struct string
    {
        explicit string(const char* const s) : m_string(s)
        {
        }

        const char* m_string = nullptr;
    };


    class string_dyn_t
    {
    public:
        void* vtbl;
        string str;
        uint32_t size;
        uint32_t capacity;
    };


#pragma pack(push, 1)
    class cache_entry_t // Size: 0x0170
    {
    public:
        cache_entry_t* next_entry; //0x0000 (0x08)
        cache_entry_t* prev_entry; //0x0008 (0x08)
        string_dyn_t path; //0x0010 (0x18)
        char pad_0028[264]; //0x0028 (0x108)
        char* content; //0x0130 (0x08)
        uint64_t size; //0x0138 (0x08)
        char pad_0140[48]; //0x0140 (0x30)
    };

    static_assert(sizeof(cache_entry_t) == 0x170);
#pragma pack(pop)


    using fs_remove_from_cache_fn = void __fastcall(
        string& path,
        uint64_t device_type
    );

    using load_unit_tree_economy_u_fn = uint64_t __fastcall(
        uint64_t a1,
        string& path,
        uint64_t a3,
        uint64_t a4
    );
}
