#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char flag[128];

void get_flag() {
    FILE *fp = fopen("flag.txt", "r");
    if (!fp) {
        perror("flag.txt");
        exit(1);
    }
    if(!fgets(flag, sizeof(flag), fp)) {
        perror("fgets");
        exit(1);
    }
    fclose(fp);

}


void vuln() {
    char buffer[64];
    int authenticated = 0;

    printf("Enter your data: ");
    fflush(stdout);

    gets(buffer);  

    if(authenticated != 0) {
        printf("Here is your flag: %s\n", flag);
    } else {
        printf("Close, but no cigar.\n");
    }
}

int main() {
    get_flag();
    setbuf(stdout, NULL);
    vuln();
    return 0;
}