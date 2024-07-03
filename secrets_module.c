#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("vareee");
MODULE_DESCRIPTION("A kernel module to store user secrets.");
MODULE_VERSION("2.0");


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
    char *input;
    int id;
    int output_len = 0;

    input = kmalloc(buffer_len + 1, GFP_KERNEL);
    if (!input) 
        return -ENOMEM;

    if (copy_from_user(input, buffer, buffer_len)) {
        kfree(input);
        return -EFAULT;
    }

    input[buffer_len] = '\0';

    sscanf(input, "%d", &id);

    if (id < 0 || id >= MAX_SECRETS || !secrets[id].used) {
        kfree(input);
        return -EINVAL;
    } 

    output = kmalloc((sizeof(struct secret)), GFP_KERNEL);
    if (!output) 
        return -ENOMEM;
    
    output_len += scnprintf(output, buffer_len, "ID: %d, Secret: %s", id, secrets[id].data);

    if (output_len == 0) {
        kfree(output);
        return 0;
    }
    
    if (copy_to_user(buffer, output, output_len)) {
        kfree(output);
        return -EFAULT;
    }
    
    kfree(output);
    return output_len;
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char *input;
    int id;
    char command;
    char *data;

    if (len > MAX_SECRET_SIZE + 2)
        return -EINVAL;

    input = kmalloc(len + 1, GFP_KERNEL);
    if (!input) return -ENOMEM;

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

    kfree(input);
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
