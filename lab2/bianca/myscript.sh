rmmod lunix.ko
make
insmod ./lunix.ko
./lunix_dev_nodes.sh
./lunix-attach /dev/ttyS0
