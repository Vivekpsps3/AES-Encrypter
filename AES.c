#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 5){
        printf("Usage: %s <input> <key> <output> <mode>\n", argv[0]);
        return 1;
    }

    //get the various arguments as strings
    char *input = argv[1];
    char *key = argv[2];
    char *output = argv[3];
    char *mode = argv[4];

    //print the arguments
    printf("Input: %s\n", input);
    printf("Key: %s\n", key);
    printf("Output: %s\n", output);
    printf("Mode: %s\n", mode);


    return 0;
}