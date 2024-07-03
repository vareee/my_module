#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>


#define PROC_FILE "/proc/secrets"
#define BUFFER_SIZE 1024


void create_secret(int id, const char *data) {
    int fd = open(PROC_FILE, O_WRONLY);

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];

    int bytes_written = snprintf(buffer, BUFFER_SIZE, "C %d %s", id, data);

    if (write(fd, buffer, bytes_written + 1) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

void read_secret(int id) {
    int fd = open(PROC_FILE, O_RDONLY);

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];

    ssize_t bytes_read;

    
    snprintf(buffer, BUFFER_SIZE, "%d", id);

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s\n", buffer);
    }

    close(fd);
}

void delete_secret(int id) {
    int fd = open(PROC_FILE, O_WRONLY);

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];

    int bytes_written = snprintf(buffer, BUFFER_SIZE, "D %d", id);

    if (write(fd, buffer, bytes_written + 1) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
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
