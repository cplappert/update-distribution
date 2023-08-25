#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

FILE *file;

int write_to_file(const void* data, int size, char* path){

    if (!path || !strcmp(path, "-")) {
        if (-1 == write (STDOUT_FILENO, data, size)) {
            fprintf (stderr, "write(2) to stdout failed: %m\n");
            return 1;
        }
        return 0;
    }    

    file = fopen(path, "wb"); //"wb+");
    if(!file){
        printf("Error: write_to_file fopen\n");
        printf("File cannot be created\n");
        return 1;
    }

    fwrite(data, size, 1, file);

    fclose(file);

    return 0;
}

int append_to_file(const void* data, int size, char* path){

    if (!path || !strcmp(path, "-")) {
        if (-1 == write (STDOUT_FILENO, data, size)) {
            fprintf (stderr, "write(2) to stdout failed: %m\n");
            return 1;
        }
        return 0;
    }    

    file = fopen(path, "a"); //"wb+");
    if(!file){
        printf("Error: append_to_file fopen\n");
        printf("File cannot be created\n");
        return 1;
    }

    fwrite(data, size, 1, file);

    fclose(file);

    return 0;
}

int read_from_file(void *data, int max_read_size, int *size, char* path){
    int rc = 0;
    if (!path || !strcmp(path, "-")) {

        char *buf = malloc(max_read_size);
        char *read_data = malloc(max_read_size);

        if (buf == fgets(buf, max_read_size, stdin)) {
            rc = sscanf(buf, "%s", read_data);
            if (rc != 1) {
                free(buf);
                free(read_data);
                return 1;
            }
        }
        else {
            free(buf);
            free(read_data);
            return 1;
        }

        strcpy(data, read_data);
        if (size){
            *size=strlen(read_data);
        }

        free(buf);
        free(read_data);
        return 0;

        // if (-1 == read (STDIN_FILENO, data, *size)) {
        //     fprintf (stderr, "read(2) from stdin failed: %m\n");
        //     return 1;
        // }
        // return 0;
    }

    file = fopen(path, "rb"); //"wb+");
    if(!file){
        printf("Error: read_from_file fopen\n");
        printf("File cannot be read\n");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if(fsize > max_read_size){
        printf("Error: Filesize of %ld bigger than expected!\n", fsize);
        return 1;
    }

    uint8_t *data_int;
    data_int = malloc(max_read_size);

    fread(data_int, fsize, 1, file);

    // for(int i = 0; i < fsize; i++){
    //     printf("%02x", data_int[i]);
    // }
    // printf("\n");
    if (size){
        *size = fsize;
    }

    memcpy(data, data_int, fsize);

    free(data_int);

    fclose(file);

    return 0;
}