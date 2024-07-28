#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("vareee");
MODULE_DESCRIPTION("A kernel module to store user secrets.");
MODULE_VERSION("4.0");


#define PROC_NAME "secrets"
#define MAX_SECRET_SIZE 1024

struct secret {
    int id;
    char data[MAX_SECRET_SIZE];
    struct list_head list;
};

static LIST_HEAD(secret_list);
static struct proc_dir_entry *proc_entry;
static DEFINE_MUTEX(secret_mutex);

static ssize_t proc_read(struct file *file_pointer, char __user *buffer, size_t buffer_len, loff_t *offset) {
    char *input, *output;
    int id;
    struct secret *sec;
    struct list_head *pos;
    int output_len = 0;

    if (*offset > 0)
        return 0;

    input = kmalloc(buffer_len + 1, GFP_KERNEL);
    if (!input)
        return -ENOMEM;

    if (copy_from_user(input, buffer, buffer_len)) {
        kfree(input);
        return -EFAULT;
    }
    input[buffer_len] = '\0';

    sscanf(input, "%d", &id);

    output = kmalloc(MAX_SECRET_SIZE + 50, GFP_KERNEL);
    if (!output) {
        kfree(input);
        return -ENOMEM;
    }

    mutex_lock(&secret_mutex);

    list_for_each(pos, &secret_list) {
        sec = list_entry(pos, struct secret, list);
        if (sec->id == id) {
            output_len = scnprintf(output, MAX_SECRET_SIZE + 50, "ID: %d, Secret: %s", sec->id, sec->data);
            break;
        }
    }

    mutex_unlock(&secret_mutex);

    if (output_len == 0) {
        kfree(output);
        kfree(input);
        return -EINVAL; 
    }

    if (copy_to_user(buffer, output, min(buffer_len, (size_t)output_len))) {
        kfree(output);
        kfree(input);
        return -EFAULT;
    }

    kfree(output);
    kfree(input);
    *offset += min(buffer_len, (size_t)output_len);
    return min(buffer_len, (size_t)output_len);
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    char *input;
    int id;
    char command;
    char *data;
    struct secret *sec, *new_sec;
    struct list_head *pos, *q;

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
    data = strchr(input + 2, ' ') + 1;

    mutex_lock(&secret_mutex);

    switch (command) {
        case 'C':
            list_for_each_safe(pos, q, &secret_list) {
                sec = list_entry(pos, struct secret, list);
                if (sec->id == id) {
                    mutex_unlock(&secret_mutex);
                    kfree(input);
                    return -EINVAL;
                }
            }

            new_sec = kmalloc(sizeof(struct secret), GFP_KERNEL);
            if (!new_sec) {
                mutex_unlock(&secret_mutex);
                kfree(input);
                return -ENOMEM;
            }

            new_sec->id = id;
            strncpy(new_sec->data, data, MAX_SECRET_SIZE);
            new_sec->data[MAX_SECRET_SIZE - 1] = '\0';

            list_add_tail(&new_sec->list, &secret_list);
            break;

        case 'D':
            list_for_each_safe(pos, q, &secret_list) {
                sec = list_entry(pos, struct secret, list);
                if (sec->id == id) {
                    list_del(&sec->list);
                    kfree(sec);
                    mutex_unlock(&secret_mutex);
                    kfree(input);
                    return len;
                }
            }
            mutex_unlock(&secret_mutex);
            kfree(input);
            return -EINVAL;

        default:
            mutex_unlock(&secret_mutex);
            kfree(input);
            return -EINVAL;
    }

    mutex_unlock(&secret_mutex);
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

    pr_info("/proc/%s created\n", PROC_NAME);
    return 0;
}

static void __exit secrets_exit(void) {
    struct secret *sec;
    struct list_head *pos, *q;

    mutex_lock(&secret_mutex);

    list_for_each_safe(pos, q, &secret_list) {
        sec = list_entry(pos, struct secret, list);
        list_del(&sec->list);
        kfree(sec);
    }

    mutex_unlock(&secret_mutex);

    proc_remove(proc_entry);
    pr_info("/proc/%s removed\n", PROC_NAME);
}

module_init(secrets_init);
module_exit(secrets_exit);

