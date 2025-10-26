#include <Windows.h>
#include <stdio.h>
#include <assert.h>

int main() {
    HMODULE lib = LoadLibrary("./tool/10000.dll");

    void *base = lib;

    for (int i = 0; i < 10000; i++) {
        HRSRC rsrc = FindResourceA(lib, (LPCSTR) i, (LPCSTR)0xa);
        HGLOBAL rcdata = LoadResource(lib, rsrc);
        int size = SizeofResource(lib, rsrc);
        char *data = (char*)LockResource(rcdata);

        int (*getSize)(char *, int, int) = (int (*)(char*, int, int))((char*)lib + 0x2690);

        int sz = getSize(data, size, 0);    

        char *decompressed = (char*)calloc(1, sz);

        
        int (*decompress)(char *, char*, int, int, int) = (int (*)(char*, char*, int, int, int))((char*)lib + 0x35E8);

        decompress(data, decompressed, size, sz, 0);

        char name[100];
        sprintf(name, "dlls/%d.dll", i);
        FILE *fp = fopen(name, "wb");
        assert(fp != NULL);
        fwrite(decompressed, 1, sz, fp);
        fclose(fp);
    }
}