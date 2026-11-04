__declspec(dllimport) void __attribute__((stdcall)) Sleep(unsigned long);
__attribute__((noinline)) int read_import(void) { Sleep(1); return 7; }
int main(void) { return read_import(); }
