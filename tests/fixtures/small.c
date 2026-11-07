int g_counter = 3;
static int helper(int x) {
    int y = x * 2;
    return y + g_counter;
}
int alpha(int a) {
    int r = helper(a);
    return r + 1;
}
int beta(int b) {
    return alpha(b) * 3;
}
int mainfn(void) {
    return beta(4);
}
