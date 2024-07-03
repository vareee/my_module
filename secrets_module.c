#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("vareee");
MODULE_DESCRIPTION("A kernel module to store user secrets.");
MODULE_VERSION("1.0");


#define PROC_NAME "secrets"
#define MAX_SECRETS 100
#define MAX_SECRET_SIZE 1024

struct secret {
    bool used;
    char data[MAX_SECRET_SIZE];
};

static struct secret secrets[MAX_SECRETS];
static struct proc_dir_entry *proc_entry;

static ssize_t proc_read(struct file *file_pointer, char __user *buffer, size_t buffer_len, loff_t *offset) {
    char *output;
    int output_len = 0;

    output = kmalloc(MAX_SECRETS * (sizeof(struct secret) + 15), GFP_KERNEL);
    if (!output) 
        return -ENOMEM;

    for (int i = 0; i < MAX_SECRETS; i++) {
        if (secrets[i].used)
            output_len += scnprintf(output + output_len, MAX_SECRET_SIZE, "ID: %d, Secret: %s", i, secrets[i].data);
    }

    if (*offset >= output_len) {
        kfree(output);
        return 0;
    }

    if (buffer_len > output_len - *offset)
        buffer_len = output_len - *offset;

    if (copy_to_user(buffer, output + *offset, buffer_len)) {
        kfree(output);
        return -EFAULT;
    }

    *offset += buffer_len;
    kfree(output);
    return buffer_len;
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char *input;
    int id;
    char command;
    char *data;

    if (len > MAX_SECRET_SIZE + 2)
        return -EINVAL;

    input = kmalloc(len + 1, GFP_KERNEL);
    if (!input) 
        return -ENOMEM;

    if (copy_from_user(input, buffer, len)) {
        kfree(input);
        return -EFAULT;
    }

    input[len] = '\0';

    sscanf(input, "%c %d", &command, &id);

    switch (command) {
        case 'C':
            if (id < 0 || id >= MAX_SECRETS || secrets[id].used) {
                kfree(input);
                return -EINVAL;
            }
            data = strchr(input + 2, ' ') + 1;
            strncpy(secrets[id].data, data, MAX_SECRET_SIZE);
            secrets[id].data[MAX_SECRET_SIZE - 1] = '\0';
            secrets[id].used = true;
            break;
        case 'D':
            if (id < 0 || id >= MAX_SECRETS || !secrets[id].used) {
                kfree(input);
                return -EINVAL;
            }
            secrets[id].used = false;
            memset(secrets[id].data, 0, MAX_SECRET_SIZE);
            break;
        default:
            kfree(input);
            return -EINVAL;
    }

    return len;
}

static const struct proc_ops proc_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init secrets_init(void) {

    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_ops);
    if (!proc_entry) {
        return -ENOMEM;
    }

    for (int i = 0; i < MAX_SECRETS; i++) {
        secrets[i].used = false;
    }

    pr_info("/proc/%s created\n", PROC_NAME);
    return 0;
}

static void __exit secrets_exit(void) {
    proc_remove(proc_entry);
    pr_info("/proc/%s removed\n", PROC_NAME);
}

module_init(secrets_init);
module_exit(secrets_exit);
