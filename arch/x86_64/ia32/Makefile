#
# Makefile for the ia32 kernel emulation subsystem.
#

obj-$(CONFIG_IA32_EMULATION) := ia32entry.o sys_ia32.o ia32_ioctl.o \
	ia32_signal.o tls32.o \
	ia32_binfmt.o fpu32.o ptrace32.o syscall32.o

sysv-$(CONFIG_SYSVIPC) := ipc32.o
obj-$(CONFIG_IA32_EMULATION) += $(sysv-y)

obj-$(CONFIG_IA32_AOUT) += ia32_aout.o

$(obj)/syscall32.o: $(src)/syscall32.c \
	$(foreach F,sysenter syscall,$(obj)/vsyscall-$F.so)

# Teach kbuild about targets
targets := $(foreach F,sysenter syscall,vsyscall-$F.o vsyscall-$F.so)

# The DSO images are built using a special linker script
quiet_cmd_syscall = SYSCALL $@
      cmd_syscall = $(CC) -m32 -nostdlib -shared -s \
			   -Wl,-soname=linux-gate.so.1 -o $@ \
			   -Wl,-T,$(filter-out FORCE,$^)

ifndef CONFIG_XEN
$(obj)/vsyscall-sysenter.so $(obj)/vsyscall-syscall.so: \
$(obj)/vsyscall-%.so: $(src)/vsyscall.lds $(obj)/vsyscall-%.o FORCE
	$(call if_changed,syscall)

AFLAGS_vsyscall-sysenter.o = -m32
AFLAGS_vsyscall-syscall.o = -m32
CFLAGS_ia32_ioctl.o += -Ifs/
else
obj-y += syscall32_syscall-xen.o
$(obj)/vsyscall-int80.so \
$(obj)/vsyscall-sysenter.so $(obj)/vsyscall-syscall.so: \
$(obj)/vsyscall-%.so: $(src)/vsyscall.lds $(obj)/vsyscall-%.o FORCE
	$(call if_changed,syscall)

AFLAGS_vsyscall-sysenter.o = -m32 -Iarch/i386/kernel
AFLAGS_vsyscall-syscall.o = -m32 -Iarch/i386/kernel
AFLAGS_vsyscall-int80.o = -m32 -Iarch/i386/kernel
CFLAGS_ia32_ioctl.o += -Ifs/
CFLAGS_syscall32-xen.o += -DUSE_INT80
AFLAGS_syscall32_syscall-xen.o += -DUSE_INT80

$(obj)/syscall32_syscall-xen.o: $(src)/syscall32_syscall-xen.S \
	$(foreach F,int80 sysenter syscall,$(obj)/vsyscall-$F.so)

$(obj)/syscall32-xen.o: $(src)/syscall32-xen.c \
	$(foreach F,sysenter syscall,$(obj)/vsyscall-$F.so)

targets := $(foreach F,int80 sysenter syscall,vsyscall-$F.o vsyscall-$F.so)

include $(srctree)/scripts/Makefile.xen

obj-y := $(call cherrypickxen, $(obj-y))
endif
