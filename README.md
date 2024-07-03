# Usage

### kernel module

To build the module download Makefile and secrets_module.c and put these files in the same folder. Then use ***make*** to build it. After this step you can load the module in kernel using ***insmod secrets_module.ko*** and unload it using ***rmmod secrets_module***.

### user_app

To compile type ***gcc -o user_app user_app.c***

**Usage**: ./user_app \<command> [args]

|Commands|Description|
|-|--------|
|create \<id> \<data>|Create a new secret with the given id and data|
|read \<id>|Read the secret with the given id|
|delete \<id>|Delete the secret with the given id|
