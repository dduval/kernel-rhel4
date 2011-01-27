#
# Makefile for sensor chip drivers.
#

obj-$(CONFIG_HWMON)		+= hwmon.o
obj-$(CONFIG_HWMON_VID)		+= hwmon-vid.o
obj-$(CONFIG_SENSORS_ADM1026) 	+= adm1026.o
obj-$(CONFIG_SENSORS_LM87) 	+= lm87.o

ifeq ($(CONFIG_HWMON_DEBUG_CHIP),y)
EXTRA_CFLAGS += -DDEBUG
endif

