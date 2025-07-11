obj-m += ouichefs.o
ouichefs-objs := fs.o super.o inode.o file.o dir.o

KERNELDIR_LKP ?= /home/christianwichmann/sciebo/02_Studium_ComputerEngineering/Master_1.Semester/LKP_Desktop/linux


all:
	make -C $(KERNELDIR_LKP) M=$(PWD) modules

debug:
	make -C $(KERNELDIR_LKP) M=$(PWD) ccflags-y+="-DDEBUG -g" modules

clean:
	make -C $(KERNELDIR_LKP) M=$(PWD) clean
	rm -rf *~

.PHONY: all clean
