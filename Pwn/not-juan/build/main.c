#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char *radio_broadcasts[] = {
    "\"Signal strong, mission clear.\"",
    "\"Time to tune in, the airwaves await.\"",
    "\"Keep the frequency alive, agents!\""
};

int main(void) {
    srand(time(0));
    long radio_index = rand() % (sizeof(radio_broadcasts) / sizeof(char *));
    char transmission[32];
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    puts(radio_broadcasts[radio_index]);
    puts("ALERT: The secret radio station 'Silent Frequency' has lost contact with base!");
    puts("Transmit a coded message to restore the signal:");
    gets(transmission);
    if(radio_index == -1)
        system("/bin/sh");
    return 0;
}

