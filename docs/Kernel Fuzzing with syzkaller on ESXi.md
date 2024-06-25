Finding the proper infrastructure to fuzz the Linux kernel can be a tricky thing. You don't want to do it on your daily use machine since it'll hog up all the resources and get in the way of work. You also need something that will keep running 24/7 without interruption for at least a few months. Enter V-Lab.

# V-Lab
V-Lab is the VMWare ESXi set up that I have at my workplace. It runs on a machine with the following specs:
- Intel Xeon E5-2660v4 with 24 cores and 56 threads @ 2.00 GHz
- 64 GB Memory 
- 2.0 TB Disk Space

Not the most powerful server you could use for fuzzing but it can get the job done.

# Virtual Machines
Initially I decided to go the simple old route of setting up one mega VM with loads of CPU cores and memory, and use nested virtualization to spin up further VMs for fuzzing the kernel. I quickly ran into lots of issues however. SSH refused to work inside my nested VMs when syzkaller tried to spin them up automatically. Even if I resolved those issues I would still end up with sub-par performance due to nested virtualization.

Then I decided to go for the following set up:
- ### Controller VM
	- OS: Ubuntu 22.04 LTS
	- Cores: 8
	- Memory: 16 GB
	- Hard Disk: 50 GB
- ### Fuzz VMs
	- Count: 10
	- OS: Arch Linux
	- Cores: 2
	- Memory: 2 GB
	- Hard Disk: 8 GB 

# Setting up the Controller VM
