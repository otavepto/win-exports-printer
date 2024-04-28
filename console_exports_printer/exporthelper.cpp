#include "exporthelper.hpp"
//#include <winternl.h>

namespace exporthelper
{
    __forceinline static PIMAGE_SECTION_HEADER section_headers_x64(PIMAGE_NT_HEADERS64 nt_header, PIMAGE_FILE_HEADER file_header)
    {
        PIMAGE_OPTIONAL_HEADER64 optional_header = (PIMAGE_OPTIONAL_HEADER64)&nt_header->OptionalHeader;
        WORD optional_headr_size = file_header->SizeOfOptionalHeader;

        return (PIMAGE_SECTION_HEADER)((char*)optional_header + optional_headr_size);
    }

    __forceinline static PIMAGE_SECTION_HEADER section_headers_x32(PIMAGE_NT_HEADERS32 nt_header, PIMAGE_FILE_HEADER file_header)
    {
        PIMAGE_OPTIONAL_HEADER32 optional_header = (PIMAGE_OPTIONAL_HEADER32)&nt_header->OptionalHeader;
        WORD optional_headr_size = file_header->SizeOfOptionalHeader;

        return (PIMAGE_SECTION_HEADER)((char*)optional_header + optional_headr_size);
    }


    __forceinline static PIMAGE_DATA_DIRECTORY data_directory_x64(PIMAGE_NT_HEADERS64 nt_header)
    {
        PIMAGE_OPTIONAL_HEADER64 optional_header = (PIMAGE_OPTIONAL_HEADER64)&nt_header->OptionalHeader;
        return optional_header->DataDirectory;
    }

    __forceinline static PIMAGE_DATA_DIRECTORY data_directory_x32(PIMAGE_NT_HEADERS32 nt_header)
    {
        PIMAGE_OPTIONAL_HEADER32 optional_header = (PIMAGE_OPTIONAL_HEADER32)&nt_header->OptionalHeader;
        return optional_header->DataDirectory;
    }


    __forceinline static bool valid_pe_header(const char *file_buff)
    {
        if (!file_buff) return false;

        // https://dev.to/wireless90/validating-the-pe-signature-my-av-flagged-me-windows-pe-internals-2m5o/
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buff;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false; // "MZ"

        LONG new_header_offset = dos_header->e_lfanew;
        PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(file_buff + new_header_offset);
        if (nt_header->Signature != IMAGE_NT_SIGNATURE) return false; // "PE\0\0"

        PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader;
        if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64 && file_header->Machine != IMAGE_FILE_MACHINE_I386) return false;

        PIMAGE_SECTION_HEADER section_headers = nullptr;
        PIMAGE_DATA_DIRECTORY data_directory = nullptr;
        if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            section_headers = section_headers_x64((PIMAGE_NT_HEADERS64)nt_header, file_header);
            data_directory = data_directory_x64((PIMAGE_NT_HEADERS64)nt_header);
        }
        else
        {
            section_headers = section_headers_x32((PIMAGE_NT_HEADERS32)nt_header, file_header);
            data_directory = data_directory_x32((PIMAGE_NT_HEADERS32)nt_header);
        }

        if (!section_headers) return false;
        DWORD sections_count = file_header->NumberOfSections;
        if (!sections_count) return false;

        if (!data_directory) return false;
        PIMAGE_DATA_DIRECTORY exports_dir_info = &data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!exports_dir_info->Size || !exports_dir_info->VirtualAddress) return false;

        return true;
    }

    __forceinline static PIMAGE_DATA_DIRECTORY get_exports_dir_info(const char *file_buff)
    {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buff;
        LONG new_header_offset = dos_header->e_lfanew;
        PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(file_buff + new_header_offset);
        PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader;

        PIMAGE_DATA_DIRECTORY data_directory = nullptr;
        if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            data_directory = data_directory_x64((PIMAGE_NT_HEADERS64)nt_header);
        }
        else
        {
            data_directory = data_directory_x32((PIMAGE_NT_HEADERS32)nt_header);
        }

        return &data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    // https://stackoverflow.com/a/61108440
    __forceinline static const void* rva_to_disk_offset(const char *file_buff, DWORD rva)
    {
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buff;
        LONG new_header_offset = dos_header->e_lfanew;
        PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(file_buff + new_header_offset);
        PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader;

        PIMAGE_SECTION_HEADER section_headers = nullptr;
        if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            section_headers = section_headers_x64((PIMAGE_NT_HEADERS64)nt_header, file_header);
        }
        else
        {
            section_headers = section_headers_x32((PIMAGE_NT_HEADERS32)nt_header, file_header);
        }

        // find the section containing this RVA
        for (DWORD sIdx = 0; sIdx < file_header->NumberOfSections; ++sIdx)
        {
            PIMAGE_SECTION_HEADER current_section = &section_headers[sIdx];
            DWORD current_section_span = current_section->VirtualAddress + current_section->SizeOfRawData;
            if (rva >= current_section->VirtualAddress && rva < current_section_span) // RVA is inside this section's range
            {
                DWORD offset_from_my_section = rva - current_section->VirtualAddress;
                /*
                * file_buff:                         absolute file base (absolute starting address)
                * current_section->PointerToRawData: disk offset for the beginning of this section (relative to file_buff)
                * offset_from_my_section:            how many bytes from the beginning of **this section**
                */
                return file_buff + current_section->PointerToRawData + offset_from_my_section;
            }

        }

        // invalid RVA (outside all sections) or malformed PE header
        return nullptr;
    }

}

void exporthelper::traverse_exports(const char *file_buff, ExportIteratorCb_t callback)
{
    if (!file_buff || !callback || !valid_pe_header(file_buff)) return;

    PIMAGE_DATA_DIRECTORY exports_dir_info = get_exports_dir_info(file_buff);

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
    PIMAGE_EXPORT_DIRECTORY exports_dir = (PIMAGE_EXPORT_DIRECTORY)rva_to_disk_offset(file_buff, exports_dir_info->VirtualAddress);
    // the starting number for the exports
    DWORD ordinals_base = exports_dir->Base;
    // list of RVAs, each DWORD is an RVA
    const DWORD *functions_rvas = (const  DWORD *)rva_to_disk_offset(file_buff, exports_dir->AddressOfFunctions);
    // array of Names RVAs, each DWORD is a name RVA
    const DWORD *names_rvas = (const  DWORD *)rva_to_disk_offset(file_buff, exports_dir->AddressOfNames);
    // array of ordinals, each WORD is an ordinal, an ordinal = RVA_table_index
    const WORD *ordinals_list = (const WORD *)rva_to_disk_offset(file_buff, exports_dir->AddressOfNameOrdinals);

    for (DWORD fIdx = 0; fIdx < exports_dir->NumberOfFunctions; fIdx++)
    {
        // https://devblogs.microsoft.com/oldnewthing/20121116-00/?p=6073
        // automatically padded exports, added by compiler/linker between non consecutive exports
        /*
         * LIBRARY "my_dll"
         * EXPORTS
         *
         *    MyNamedExport               @1
         *                                              <<< auto padding is added here
         *    MyHiddenFuncWithOrdinal_1   @112 NONAME
         *                                              <<< auto padding is also added here
         *    MyHiddenFuncWithOrdinal_2   @212 NONAME
         */
        DWORD function_rva = functions_rvas[fIdx];
        if (!function_rva) continue; // if this is a linker padding

        // https://reverseengineering.stackexchange.com/a/8380
        /*
         * n  name            address
         * ---------------|-----------
         * 0  funca       |   12345678
         * 1  <NO NAME>   |   9abcdef0
         * 2  funcb       |   76543210
         * 3  <NO NAME>   |   fedcba98
         * @@@@@@@@@@@@@@@@@@@@@@@@@@@
         * address table entries   = 4
         * number of name pointers = 2
         * export address table    = [ 12345678, 9abcdef0, 76543210, fedcba98 ]
         * name pointer table      = [ funca, funcb ]
         * ordinal table           = [ 0    , 2 ]
         */
        // search for the current index inside the list of named exports
        const char* function_name = nullptr;
        for (DWORD searchIdx = 0; searchIdx < exports_dir->NumberOfNames; searchIdx++)
        {
            // if current index is in the list of named exports
            if ((DWORD)ordinals_list[searchIdx] == fIdx)
            {
                // grab the name RVA from the equivalent place in the names RVAs table
                DWORD name_rva = names_rvas[searchIdx];
                function_name = (const char*)rva_to_disk_offset(file_buff, name_rva);
                break;
            }
        }

        // from the docs, the ordinal value is just the index we got from the 'ordinal list' + the bias value
        DWORD function_ordinal = fIdx + ordinals_base;

        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
        // if function RVA is forwarded to the name of the actual provider
        // TODO load actual provider and get the export's real address
        if ((function_rva >= exports_dir_info->VirtualAddress) &&
            (function_rva < (exports_dir_info->VirtualAddress + exports_dir_info->Size)))
        {
            // functionRva now points at the export detils in the .rdata
            // ModuleName.Some_Export or ModuleName.#24
            // happens when the export is borrowed from another dll,
            // in that case, this address isn't useful
            // CFF Explorer will display that address anyway

        }

        callback(function_name, function_ordinal, function_rva, file_buff);
    }
}
