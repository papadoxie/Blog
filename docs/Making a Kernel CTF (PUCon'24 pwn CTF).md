Recently I had the pleasure of designing some challenges for a CTF held at my alma mater, University of the Punjab. Despite having reasonable experience with solving kernel challenges in the past, this was my first time actually making a kernel challenge on my own.

The idea was pretty simple, write a module that had a simple buffer overflow that led to RIP control. The execution however, was not that simple, so I decided to write this blog to document everything it took to set my challenges up.

## Environment
The challenge was going to be hosted on CTFd's managed hosting so it had to be able to run in a Docker container. Since the container was going to run on CTFd infrastructure, we couldn't be sure what kernel we were going to get. To get past this we decided to run our challenge inside a `qemu` VM inside our container.  

### VM
Initially for the guest OS, we went with the syzcaller debootstrap script (https://github.com/google/syzkaller/blob/master/tools/create-image.sh) that sets up a fully featured Debian image for us.  After setting it up we found out the VM was using way more memory than what CTFd allowed for one container so we switched to using a simple `initramfs` with `busybox` setup.  
Our setup was similar to `hxp-ctfs` kernel ROP challenge (https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) with a modified `run.sh` script.

```bash
read -p "Enter the link to your exploit binary: " link

wget $link -O exploit
chmod 777 ./exploit
sleep 1
./decompress.sh
rm intramfs/exploit
cp ./exploit initramfs/
./compress.sh

qemu-system-x86_64 \
  -snapshot \
  -kernel kernel/arch/x86/boot/bzImage \
  -smp cores=1,threads=1 \
  -initrd initramfs.cpio.gz \
  -append "console=ttyS0 debug earlyprintk=serial oops=panic nokaslr smap smep selinux=0 pti tsc=unstable net.ifnames=0 panic=1000 cgroup_disable=memory" \
  -net nic -net user,hostfwd=tcp::${SSH_PORT}-:22 \
  -nographic \
  -m 128M \
  -monitor none,server,nowait,nodelay,reconnect=-1 \
  -cpu kvm64,+smap,+smep \
  2>&1
```

Since the exploit was supposed to run locally on the VM, we provided a way for the contestants to upload their exploit as soon as they connected by reading in a link at the start and downloading a file from there and putting it in the `initramfs`.

### Container
The container environment was pretty simple. `cpio` and `gzip` were required to modify the `initramfs` and put the contestants exploits into the VM. `wget` was used to download the exploit. `qemu` was used to run the VM.  

```dockerfile
FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y qemu qemu-system-x86 qemu-utils socat cpio gzip wget 

EXPOSE 1337

RUN useradd -d /home/ctf -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
RUN ulimit -c 0

WORKDIR /home/ctf
COPY kernel ./kernel
COPY run.sh ./run.sh
COPY initramfs.cpio.gz ./initramfs.cpio.gz
COPY compress.sh ./compress.sh
COPY decompress.sh ./decompress.sh
RUN chmod +x *.sh
RUN chmod 666 ./initramfs.cpio.gz

EXPOSE 1337
USER ctf
CMD socat tcp-l:1337,reuseaddr,fork EXEC:"./run.sh",pty,stderr
```

Initially we used `ynetd` to serve the challenge but for some reason, one night before the CTF was supposed to star, `ynetd` decided to bail on us and started sending EOF on `stdin` as soon as we attempted to connect. For this reason we shifted to using `socat`. Unfortunately this meant the shell that was served was unstable by default and we only figured out how to connect to it stably after the competition ended. Fortunately the kernel challenges were able to be solved with unstable shells.
```bash
socat file:`tty`,raw,echo=0 tcp:<challenge-link>:<port>
```

## Kernel
The kernel we chose was `v6.6.16` and we applied some of our own patches to make it easier to exploit.

### Added Exports
Some symbols were exported so we could directly use them to make a win function in our module.
`kernel/cred.c`
```c
64 | EXPORT_SYMBOL(init_cred)
``` 
`kernel/reboot.c`
```c
832 | EXPORT_SYMBOL(run_cmd)
```

### Removing Safety Checks in Code
We had to remove the size check in `copy_to_user` and `copy_from_user` to make sure our module would actually receive more bytes than the buffer could hold.
```c {include/linux/uaccess.h}
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	// if (check_copy_size(to, n, false))
		n = _copy_from_user(to, from, n);
	return n;
}

static __always_inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
	// if (check_copy_size(from, n, true))
		n = _copy_to_user(to, from, n);
	return n;
}
```

### Removing Safety Checks in Config
We used `defconfig` which was based on `x86_64_defconfig` and edited it to turn off mitigations.
`.config`
```config
CONFIG_CC_HAS_RETURN_THUNK=n
CONFIG_CALL_PADDING=n
CONFIG_HAVE_CALL_THUNKS=n
CONFIG_CALL_THUNKS=n
CONFIG_PREFIX_SYMBOLS=n
CONFIG_RETPOLINE=n
CONFIG_RETHUNK=n
CONFIG_CPU_UNRET_ENTRY=n
CONFIG_CALL_DEPTH_TRACKING=n
CONFIG_CPU_IBPB_ENTRY=n
CONFIG_CPU_IBRS_ENTRY=n
CONFIG_CPU_SRSO=n
CONFIG_STACKPROTECTOR=n
CONFIG_STACKPROTECTOR_STRONG=n
```

Retpoline and return thunk proved hard to turn off for some reason. Setting their variables to `n` wouldn't work and they'd get set to `y` as soon as we started the build. To get past this we had to remove the options directly from `arch/x86/Kconfig`

## Vulnerable Module
The module was pretty simple. It created a device that you could write to and read from. The vulnerability was in the unchecked read by the `copy_from_user` function that we patched earlier. `copy_from_user` was used to read unbounded data written from user-space into a kernel buffer of size 256 bytes.  

We added a `file_sending_system` win function that escalated privileges using `commit_creds(&init_cred)` and then read a file from the file-system using the `kernel_read_file_from_path` function defined in `fs/kernel_read_file.c`. We had to add pragmas to ensure this function would not be optimized out by the compiler since it wasn't being called anywhere.
```c
MODULE_LICENSE("GPL");
MODULE_AUTHOR("papadoxie");
MODULE_DESCRIPTION("Kernel Messaging System");
MODULE_VERSION("1337");

static int majorNumber;
static char *message_to_return = NULL;
static int size_of_message;
static struct class *messageClass = NULL;
static struct device *messageDevice = NULL;

static struct file_operations fops =
{
        .open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

#pragma GCC push_options
#pragma GCC optimize("O0")
__attribute__((unused)) 
__attribute((noreturn))
volatile static int file_sending_system(void)
{
    printk(KERN_INFO "Messager: In the future I'll be able to send files to the kernel too!\n");
    printk(KERN_INFO "Messager: No need to enable this function since it isn't completed\n");

    char *file_path = "/root/flag.txt";
    loff_t offset = 0;
    size_t bufsize = 64;
    size_t filesize = 4096;
    enum kernel_read_file_id id = 0;
    void *file_buf = kmalloc(bufsize, GFP_KERNEL);

    commit_creds(&init_cred);
    kernel_read_file_from_path(file_path, offset, &file_buf, bufsize, &filesize, id);
    printk(KERN_INFO "Messager: File content: %s\n", (char *)file_buf);
    while(1)
        ;
}
#pragma GCC pop_options

static int __init mod_init(void)
{
    printk(KERN_INFO "#####################################################################################\n");
    printk(KERN_INFO "\tPAPADOXIE'S EASY KERNEL MESSAGING SYSTEM\n");
    printk(KERN_INFO "\tTransfer your message to the kernel and get a response back promptly!\n");
    printk(KERN_INFO "\tMessager: Initializing......\n");
    printk(KERN_INFO "#####################################################################################\n");


    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        printk(KERN_ALERT "Messager: Failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "Messager: Registered correctly with major number %d\n", majorNumber);

    messageClass = class_create(CLASS_NAME);
    if (IS_ERR(messageClass))
    {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Messager: Failed to register device class\n");
        return PTR_ERR(messageClass);
    }
    printk(KERN_INFO "Messager: Device class registered correctly\n");

    messageDevice = device_create(messageClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(messageDevice))
    {
        class_destroy(messageClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(messageDevice);
    }
    printk(KERN_INFO "Messager: device class created correctly\n");
    return 0;
}

static void __exit mod_exit(void)
{
    device_destroy(messageClass, MKDEV(majorNumber, 0));
    class_unregister(messageClass);
    class_destroy(messageClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_INFO "Messager: Goodbye from the LKM!\n");
}

static int dev_open(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "Messager: Kernel communication link established\n");
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;
    error_count = copy_to_user(buffer, message_to_return, size_of_message);

    if (error_count == 0)
    {
        printk(KERN_INFO "Messager: Sent %d characters to the user\n", size_of_message);
        kfree(message_to_return);
        return (size_of_message = 0);
    }
    else
    {
        printk(KERN_INFO "Messager: Failed to send %d characters to the user\n", error_count);
        return -EFAULT;
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    char message[256];
    if (copy_from_user(message, buffer, len))
    {
        printk(KERN_ALERT "Messager: Failed to copy data from user\n");
        return -EFAULT;
    }

    message_to_return = kmalloc(len, GFP_KERNEL);
    memcpy(message_to_return, message, len);

    size_of_message = len;
    printk(KERN_INFO "Messager: Received %zu characters from the user\n", len);
    return len;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "Messager: Device successfully closed\n");
    return 0;
}

module_init(mod_init);
module_exit(mod_exit);
```

## Deployment
After setting all that up locally, it was time to deploy the challenge on CTFd. This was as simple as deploying any other challenge. First we built the Docker image for the challenge and tagged it. Then we pushed it to the CTFd repo and it miraculously worked...... after 3 days of debugging and rewriting.