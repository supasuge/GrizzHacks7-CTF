#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned int secret = 0;
char flag[128];

void get_flag() {
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("flag.txt");
        exit(1);
    }
    if (!fgets(flag, sizeof(flag), fp)) {
        perror("fgets");
        exit(1);
    }
    fclose(fp);
}

int main() {
    get_flag();
    setbuf(stdout, NULL);
    puts("Welcome to the Easy Format String Challenge!");
    puts("Enter your input:");

    char buf[256];
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;  // remove newline

    // Vulnerable usage: user controls the format string
    printf(buf);

    // Check if 'secret' has been overwritten to target value (0x41424344)
    if (secret == 0x41424344) {
        printf("\nCongratulations! Here is your flag: %s\n", flag);
    } else {
        printf("\nIncorrect secret value. Try again!\n");
    }
    return 0;
}

