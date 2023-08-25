int write_to_file(const void* data, int size, char* path);
int append_to_file(const void* data, int size, char* path);
int read_from_file(void* data, int max_read_size, int *size, char* path);