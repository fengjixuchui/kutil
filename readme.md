# kernel utility header

* KLDR_DATA_TABLE_ENTRY* get_module_entry(const wchar_t* module_name);
* KLDR_DATA_TABLE_ENTRY* get_module_entry(const u64 module_base);
* PDRIVER_OBJECT get_driver_object(const wchar_t* object_name);
* u64 get_module_base(const wchar_t* module_name);
* bool is_inside_module(const wchar_t* module_name, u64 address);
* bool is_inside_module(u64 module_address, u32 module_size, u64 address);
* bool is_inside_module(u64 address);
* UNICODE_STRING get_module(u64 address);
* NTSTATUS dump_memory_to_disk(u64 address, u32 size, const wchar_t* file_path);
* u64 get_kernel_base();
* u32 get_kernel_size();
* u64 get_routine(const wchar_t* routine_name);
* u64 get_exported_routine(const wchar_t* module_name, const char* routine_name);
* u64 get_exported_routine(const u64 module_base, const char* routine_name);
* u64 get_process_base(u32 pid);
* u64 get_process_peb(u32 pid);
* PEPROCESS get_process(const wchar_t* process_name);
* u64 signature_scan(u64 base_address, u32 scan_region, const char* pattern, const char* mask);
* u64 signature_scan(u64 base_address, const char* section_name, const char* pattern, const char* mask);
* void sleep(u32 milliseconds);

# pe

* PIMAGE_DOS_HEADER get_dos_header(u64 base_address);
* PIMAGE_NT_HEADERS64 get_nt_header_64(u64 base_address);
* PIMAGE_SECTION_HEADER get_image_section(u64 base_address, const char* section_name);