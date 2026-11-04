extern int value;
__attribute__((noinline)) int read_value(void) { return value; }
int value = 7;
int main(void) { return read_value(); }
