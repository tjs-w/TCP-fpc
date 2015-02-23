# TCP-fpc: False Positive Checksum for TCP

TCP-fpc is based on the TCP checksum shortcomings discussed in the paper:

_Jonathan Stone, Michael Greenwald, Craig Partridge, and James Hughes. 1998.
Performance of checksums and CRC's over real data. 
IEEE/ACM Trans. Netw. 6, 5 (October 1998), 529-543. DOI=10.1109/90.731187 
http://dx.doi.org/10.1109/90.731187_

__Pigeonhole principle:__ If n items are put into m containers, with n > m,
then at least one container must contain more than one item.

This leads to false positive cases with a fairly high frequency in high-speed
networks.

This kernel module enables to corrupt ingress TCP segments/data, that still
will possess the same checksum. This is meant for *TESTING* the
applications for the scenarios when the TCP fails to catch the data
corruption through its humble, feable 16-bit checksum.

## Compile

Under the dir .../TCP-fpc/ do:
```bash
make
```
To install it in modules dir:
```bash
sudo make install
```

To clean:
```bash
make clean
```

Remake:
```bash
make clean all install
```

## Usage

Making the module creates fptcp.ko. Insert this module as:
```bash
sudo insmod fptcp.ko
```

The module insertion fails if the configfs is not mounted prior. Sometimes it could be premounted at `/sys/kernel/config/` or you can just mount it at `/config/` as shown below.
```bash
sudo mount -t configfs none /config/
```

You can get the mount point by simple bash command `mount | grep configfs`. On insertion, the following config files will be created at the mount point, that help in communicating the rules and commands to and from the kernel.

\(*CONFIGFS_MOUNT* is mount-point for configfs filesystem.\)

* **CONFIGFS_MOUNT/fptcp/enable   	\- \[RW\] Enable disable the functionality.**
CONFIGFS_MOUNT/fptcp/enable reads '0' initially. You must write '1' to 
activate the functionality. If the rules are not present, but enable is '1', 
module shall tap all packets but will not do anything. If the rules are 
present, but enable is '0', the packets are not tapped and the module though 
inserted into the kernel will affect any performance.

* **CONFIGFS_MOUNT/fptcp/store_rules  \- \[WO\] Install/remove the rules.**
CONFIGFS_MOUNT/fptcp/store_rules allows 2 commands and 5 tuple rule.
Commands>
    ADD                 : cmd=add
    DEL                 : cmd=del
NOTE:
All these tokens ought to be comma-separated. No whitespaces!
Maximum of 64 rules can be installed.

* **CONFIGFS_MOUNT/fptcp/show_rules   \- \[RO\] View currently installed rules.**
CONFIGFS_MOUNT/fptcp/show_rules displays the rules installed in tabular format.

* **CONFIGFS_MOUNT/fptcp/flush_rules  \- \[WO\] Reset/uninstall all the rules.**
CONFIGFS_MOUNT/fptcp/flush_rules uninstalls all the rules installed when '1' is
written to it.

## Examples
```bash

# Mount point of configfs
CFGFS=/sys/kernel/config/

# Enable/disable tapping the IP packets
echo 1 > $CFGFS/fptcp/enable
echo 0 > $CFGFS/fptcp/enable  	# This is as good as not having any checks in the net flow, even though the module is inserted.

cat $CFGFS/fptcp/enable   	# Read enable

# Install/remove rules. Delimiter is comma \(,\). No whitespaces!
echo 'cmd=add,s_ip=74.125.224.72.10.0.1,s_port=80,d_ip=192.101.9.18,d_port=80827,perc=50' \
		 > $CFGFS/fptcp/store_rules
echo 'cmd=del,s_ip=74.125.224.72.10.0.1,s_port=80,d_ip=192.101.9.18,d_port=80827,perc=50' \
		 > $CFGFS/fptcp/store_rules


# View installed rules in tabular format
cat $CFGFS/fptcp/show_rules

# Reset to no rules
echo 1 > $CFGFS/fptcp/flush_rules

```

