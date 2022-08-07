# netscan

This is an API adaption to the Original RustScan, which extends it's functionality for use as a native Python module e.g. Extension Module.

All Credits go to the original Authors which can be found here:
https://github.com/RustScan/RustScan

As of this commit, the Wheels distribution is built via RustScan version: 2.1.0 Release.

# How to Use.

Using the module is simple. Simply install the dependency via pip.

The default Batch Size is set to 10. The batch size is essentially the number of concurrent ports to check at a time e.g. check 10 ports at a time.

The default timeout (time to wait for a TCP timeout) is 1.5 seconds (1500 miliseconds).

Note that these are extremley conservative defaults and hence lead to low performance. To increase the performance for you're environment tweak these by setting the environment variables.

Here is a final example of how to use the NetScan extension module:

```python
>>> import os, netscan
>>> # Sets the concurrent number of ports to check at a time to 1500!
>>> os.environ["SCAN_BATCH_SIZE"] = "1500"
>>> # Sets the TCP Timeout to 0.5 seconds
>>> os.environ["SCAN_TIMEOUT"] = "500"
>>> netscan.run_scan(["10.0.0.1","10.0.0.28"])
>>> ['10.0.0.1:53', '10.0.0.1:80', '10.0.0.28:135', '10.0.0.28:139', '10.0.0.28:445', '10.0.0.1:443', '10.0.0.28:3389', '10.0.0.28:7680', '10.0.0.1:8080', '10.0.0.1:8181', '10.0.0.1:21515', '10.0.0.28:27036', '10.0.0.1:49152', '10.0.0.1:49153', '10.0.0.1:49154', '10.0.0.28:49670', '10.0.0.28:57621']
>>> exit()
```

Cheers!
