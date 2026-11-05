extern int helper(int);
__attribute__((noinline)) int apply(int x) { return helper(x) + 1; }
__attribute__((noinline)) int helper(int x) { return x * 2; }
__attribute__((noinline)) int other(int x) { return x * 3; }
int main(void) { return apply(3); }
