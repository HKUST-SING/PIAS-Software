## Description

The kernel module of PIAS (<strong>P</strong>ractical <strong>I</strong>nformation-<strong>A</strong>gnostic flow <strong>S</strong>cheduling). The kernel module matains the per-flow state (`flow.h` and `flow.c`) and marks packets with different priorities (DSCP) (`network.h` and `network.c`).

## Compiling
 I have tested this kernel module with Linux kernel 2.6.38.3 and 3.18.11. You need the kernel headers to compile it:  

<pre><code>$ cd pias4<br/>
$ make</code></pre>

Then you can get a kernel module called `pias.ko`. 

## Installing 
`pias.ko` hooks into the data path using `Netfilter` hooks. To install it:
<pre><code>$ insmod pias.ko<br/>
$ dmesg|tail<br/>
PIAS: start on any interface (TCP port 0)<br/>
</code></pre>

By default, `pias.ko` filters all TCP packets (0=all) on all NICs. You can also specify the NIC and TCP port number. For exmaple, 
to make `pias.ko` only filters TCP packets whose (source or destination) port numbers are 5001 on eth1:
<pre><code>$ insmod pias.ko param_dev=eth1 param_port=5001<br/>
$ dmesg|tail<br/>
PIAS: start on eth1 (TCP port 5001)<br/>
</code></pre>

To remove the packet tagging module:
<pre><code>$ rmmod pias<br/>
$ dmesg|tail<br/>
PIAS: stop working
</code></pre>

## Usage
PIAS packet tagging module exports two types of configurations interfaces: a sysfs file to control flow table and several sysctl interfaces to configure priority parameters (see `params.h` and `params.c` for their definitions).

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
<pre><code>$ sysctl pias.prio_dscp_0<br/>
pias.prio_dscp_0 = 0
</code></pre>

To set the first demoting threshold to 50KB:
<pre><code>$ sysctl -w pias.prio_thresh_0=51200
</code></pre>

