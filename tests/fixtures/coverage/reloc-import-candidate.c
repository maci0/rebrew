__declspec(dllimport) void __attribute__((stdcall)) Sleep(unsigned long);
int read_import(void) { Sleep(1); return 7; }
