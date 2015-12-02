## Description

The kernel module of PIAS (<strong>P</strong>ractical <strong>I</strong>nformation-<strong>A</strong>gnostic flow <strong>S</strong>cheduling). The kernel module matains the per-flow state (`flow.h` and `flow.c`) and marks packets with different priorities (DSCP) (`network.h` and `network.c`).

## Compiling
 I have tested this kernel module with Linux kernel 2.6.38.3 and 3.18.11. You need the kernel headers to compile it:  

<pre><code>$ cd pias3<br/>
$ make</code></pre>

Then you can get a kernel module called `pias.ko`. Note that the anti-starvation mechanism (`DANTI_STARVATION` in Makefile) is disabled by default. Under such setting, for a flow experiencing several consecutive TCP timeouts, we will reset its bytes sent information back to 0. You can also modify Makefile to enable it. 

## Installing 
The packet tagging module hooks into the data path using `Netfilter` hooks. To install it:
<pre><code>$ insmod pias.ko param_dev=eth2<br/>
$ dmesg|tail<br/>
PIAS: start on eth2<br/>
</code></pre>

`param_dev` is the name of NIC that `pias.ko` works on. It is `eth1` by default.

To remove the packet tagging module:
<pre><code>$ rmmod pias<br/>
$ dmesg|tail<br/>
PIAS: stop working
</code></pre>

## Usage
PIAS packet tagging module exports two types of configurations interfaces: a sysfs file to control flow table and several sysctl interfaces to configure priority parameters (see `params.h` for their definitions).

To print the information of all flows in current flow table:
<pre><code>$ echo -n print > /sys/module/pias/parameters/param_table_operation<br/>
$ dmesg|tail<br/>
PIAS: current flow table<br/>
PIAS: flowlist 136<br/>
PIAS: flow record from 192.168.101.11:60410 to 192.168.101.12:5001, bytes_sent=481926280, seq=2365093177, ACK=2364897698<br/>
PIAS: flowlist 160<br/>
PIAS: flow record from 192.168.101.11:60411 to 192.168.101.12:5001, bytes_sent=578661368, seq=3795198569, ACK=3794930690<br/>
PIAS: flowlist 184<br/>
PIAS: flow record from 192.168.101.11:60412 to 192.168.101.12:5001, bytes_sent=385470656, seq=3374872543, ACK=3374742224<br/>
PIAS: flowlist 208<br/>
PIAS: flow record from 192.168.101.11:60413 to 192.168.101.12:5001, bytes_sent=433638376, seq=215506294, ACK=215310815<br/>
PIAS: there are 4 flows in total<br/>
</code></pre>

To clear all the information in current flow table:
<pre><code>$ echo -n clear > /sys/module/pias/parameters/param_table_operation<br/>
</code></pre>

To show the DSCP value of highest priority:
<pre><code>$ sysctl pias.PIAS_PRIO_DSCP_1<br/>
pias.PIAS_PRIO_DSCP_1 = 7
</code></pre>

To set the first demoting threshold to 50KB:
<pre><code>$ sysctl -w pias.PIAS_PRIO_THRESH_1=51200
</code></pre>

