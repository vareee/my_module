#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define PROC_FILE "/proc/secrets"
#define BUFFER_SIZE 1024


void create_secret(int id, const char *data) {
    int file_descriptor = open(PROC_FILE, O_WRONLY);

    if (file_descriptor == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];

    int buffer_len = snprintf(buffer, BUFFER_SIZE, "C %d %s", id, data);

    if (write(file_descriptor, buffer, buffer_len + 1) == -1) {
        perror("write");
        close(file_descriptor);
        exit(EXIT_FAILURE);
    }

    close(file_descriptor);
}

void read_secret(int id) {
    int file_descriptor = open(PROC_FILE, O_RDONLY);
    if (file_descriptor == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    int found = 0;

    while ((bytes_read = read(file_descriptor, buffer, BUFFER_SIZE)) > 0) {
        char *token = strtok(buffer, "\n");
        while (token != NULL) {
            int secret_id;
            if (sscanf(token, "ID: %d", &secret_id) == 1 && secret_id == id) {
                printf("Secret:\n%s\n", token);
                found = 1;
                break;
            }
            token = strtok(NULL, "\n");
        }

        if (found)
            break;
    }

    if (!found) {
        printf("Secret with ID %d not found\n", id);
    }

    close(file_descriptor);
}

void delete_secret(int id) {
    int file_descriptor = open(PROC_FILE, O_WRONLY);
    if (file_descriptor == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];

    int buffer_len = snprintf(buffer, BUFFER_SIZE, "D %d", id);

    if (write(file_descriptor, buffer, buffer_len + 1) == -1) {
        perror("write");
        close(file_descriptor);
        exit(EXIT_FAILURE);
    }

    close(file_descriptor);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  create <id> <data>    Create a new secret with the given id and data\n");
        fprintf(stderr, "  read <id>             Read the secret with the given id\n");
        fprintf(stderr, "  delete <id>           Delete the secret with the given id\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "create") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s create <id> <data>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        int id = atoi(argv[2]);
        create_secret(id, argv[3]);
    } else if (strcmp(argv[1], "read") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s read <id>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        int id = atoi(argv[2]);
        read_secret(id);
    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s delete <id>\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        int id = atoi(argv[2]);
        delete_secret(id);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
