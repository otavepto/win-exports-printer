#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>


namespace exporthelper
{
    typedef void (*ExportIteratorCb_t) (LPCSTR name, DWORD ordinal, DWORD rva, const char *file_buff);

    void traverse_exports(const char *file_buff, ExportIteratorCb_t callback);

}
