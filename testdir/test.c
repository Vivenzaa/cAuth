#include <stdio.h>
#include <time.h>
#include <string.h>


void test(char final[8])
{
    strcpy(final, "coucou1");
}

int main(void)
{
    char t[7];
    test(t);
    printf("%s\n", t);

    char test[32]= {1, 2, 3, 4, 5, 6, 7, 8};
    __uint64_t formatted[4] = {0, 0, 0, 0};

    //test2[2] = (*test + 3);

    //printf("t2: %d\n", test2[2]);

    formatted[0] = (__uint64_t) *test;
    //memcpy(formatted, test, sizeof(__uint64_t) * 4);

    printf("formatted[0]: %lx\n", formatted[0]);

    return 0;
}