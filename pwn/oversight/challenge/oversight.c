#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 0x100

void read_string(char *buffer, int len)
{
    int n_bytes = fread(buffer, 1, len, stdin);
    buffer[n_bytes] = '\0';
}

void get_lucky()
{
    printf("Pick a number: ");
    char num_buf[5];
    fgets(num_buf, 5, stdin);
    int num = atoi(num_buf);
    char fmt_buf[100];
    snprintf(fmt_buf, 100, "Your magic number is: %%%d$llx\n", num);
    printf(fmt_buf);
}

__attribute__((noinline)) void
echo_inner(char *buffer, int num)
{
    read_string(buffer, num);
    printf("You said:\n");
    printf("%s", buffer);
}

__attribute__((noinline)) void
echo(int num)
{
    char buffer[BUF_SIZE];
    echo_inner(buffer, num);
}

__attribute__((noinline)) void
get_num_bytes()
{
    printf("How many bytes do you want to read (max 256)? ");
    char buffer[5];
    fgets(buffer, 5, stdin);
    int num = atoi(buffer);
    if (num < 0 || num > BUF_SIZE)
    {
        printf("Don't break the rules!\n");
        return;
    }
    echo(num);
}

__attribute__((noinline)) void
introduce()
{
    volatile char wat = 0;
    printf("Are you ready to echo?\n");
    get_num_bytes();
    printf("That was fun!\n");
}

__attribute__((noinline)) void
wait()
{
    printf("Press enter to continue\n");
    getchar();
    get_lucky();
    introduce();
}

int main()
{
    setbuf(stdout, NULL);
    printf("Lets play a game\n");
    wait();
}