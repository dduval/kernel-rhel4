cmd_scripts/kconfig/conf := gcc  -o scripts/kconfig/conf scripts/kconfig/conf.o  -Wl,-rpath,\$$ORIGIN -Lscripts/kconfig -lkconfig
