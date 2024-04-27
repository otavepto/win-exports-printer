#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>

#include "exporthelper.hpp"

static void exports_iterator(LPCSTR name, DWORD ordinal, DWORD rva, const char *file_buff)
{
    if (!name) name = "<UNNAMED_EXPORT>";
    std::cout
        << "@" << std::dec << ordinal
        << "\t0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << rva
        << "\t" << name
        << std::endl;
}

static void help(const char *exe)
{
    std::cout
        << "Usage: " << exe << " D:\\my_tools\\my_lib.dll\n"
        << "Output format:\n"
        << "@ORDINAL_NUMBER <TAB> 0x<EXPORT_RVA> <TAB> <'<UNNAMED_EXPORT>' | EXPORT_NAME>\n\n"
        << "Possible output:\n"
        << "@16	0x000B8A40	<UNNAMED_EXPORT>\n"
        << "@17	0x000BA4A0	<UNNAMED_EXPORT>\n"
        << "@18	0x000BA460	<UNNAMED_EXPORT>\n"
        << "@19	0x000C20F0	<UNNAMED_EXPORT>\n"
        << "@20	0x0007A720	Direct3DCreate9On12\n"
        << "@21	0x0007A830	Direct3DCreate9On12Ex\n"
        << std::endl;
}


int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        help(argv[0]);
        return 0;
    }

    auto path = std::filesystem::path(argv[1]);
    if (!std::filesystem::is_regular_file(path))
    {
        std::cerr << "file doesn't exist\n" << std::endl;
        help(argv[0]);
        return 1;
    }

    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file)
    {
        std::cerr << "failed to read the file\n" << std::endl;
        help(argv[0]);
        return 1;
    }

    constexpr static const size_t MAX_FILE_SIZE = 50 * 1024 * 1024;
    size_t fsz = (size_t)std::filesystem::file_size(path);
    std::vector<char> buff(fsz < MAX_FILE_SIZE ? fsz : MAX_FILE_SIZE);
    file.read(&buff[0], buff.size());
    buff.resize((size_t)file.gcount());
    file.close();

    exporthelper::traverse_exports(&buff[0], exports_iterator);

    return 0;
}
