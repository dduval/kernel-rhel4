snd-azx-objs := azx.o
snd-hda-codec-objs := hda_codec.o hda_generic.o patch_realtek.o patch_cmedia.o
ifdef CONFIG_PROC_FS
snd-hda-codec-objs += hda_proc.o
endif

obj-$(CONFIG_SND_AZX) += snd-azx.o snd-hda-codec.o
