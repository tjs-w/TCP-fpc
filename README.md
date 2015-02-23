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

This kernel module enables to corrupt TCP segments/data, that still
will possess the same checksum. This is meant for *TESTING* the
applications for the scenarios when the TCP does not catch the data
corruption due to its 16-bit checksum.

## Compile

Under the dir .../TCP-fpc/ do:
```bash
        make
        sudo make install
```
To clean:
```bash
        make clean
```
## Usage

Making the module creates fptcp.ko. Insert this module as:
```bash
        sudo insmod fptcp.ko
```

OR

```bash
        sudo insmod fptcp.ko 
```

Maximum of 64 rules can be installed.


Insertion creates sysfs interface for fptcp under /sys/ as:

...CONFIGFS_MOUNT_PT/fptcp/enable   	- [RW] Enable disable the functionality.
...CONFIGFS_MOUNT_PT/fptcp/store_rules 	- [WO] Install/remove the rules.
...CONFIGFS_MOUNT_PT/fptcp/show_rules   - [RO] View currently installed rules.
...CONFIGFS_MOUNT_PT/fptcp/flush_rules  - [WO] Reset/uninstall all the rules.

\[CONFIGFS_MOUNT_PT is Mount point for configfs filesystem.\]

* /sys/fptcp/enable reads '0' initially. You must write '1' to activate
the functionality. If the rules are not present, but enable is '1',
module shall tap all packets but will not do anything. If the
rules are present, but enable is '0', the packets are not tapped
and the module though inserted into the kernel will affect any
performance.

* /sys/fptcp/store_rules allows 2 commands and 5 tuple rule.
Commands:
    ADD                 : cmd=add
    DEL                 : cmd=del
Rules:                                  (<...> is placeholder)
    SOURCE IP           : s_ip=<ip1>
    SOURCE PORT         : s_port=<port1>
    DESTINATION IP      : d_ip=<ip2>
    DESTINATION PORT    : d_port=<port2>
    PERCENT CORRUPTION  : perc=<n>
NOTE:
All these tokens ought to be comma-separated. No whitespaces!

* /sys/fptcp/show_rules displays the rules installed in tabular format.

* /sys/fptcp/flush_rules uninstalls all the rules installed when '1' is
written to it.

## Examples
```bash
    # Enable/disable tapping the IP packets
    echo 1 > /sys/fptcp/enable
    echo 0 > /sys/fptcp/enable

    cat /sys/fptcp/enable   # Read enable

    # Install/remove rules
    echo 'cmd=add,s_ip=74.125.224.72.10.0.1,s_port=80,d_ip=192.101.9.18,d_port=80827,perc=50'
    echo 'cmd=del,s_ip=74.125.224.72.10.0.1,s_port=80,d_ip=192.101.9.18,d_port=80827,perc=50'
    
    # Reset
    echo 1 > /sys/fptcp/reset

    # View installed rules in tabular format
    cat /sys/fptcp/view
```

