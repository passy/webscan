webscan
=======

`webscan` ought to be a active network scanner aimed to analyze information
retrieved from tcp headers after a SYN connect.

What's actually working is getting an approximate uptime of a given host,
running a tcp service at port 80 as long it's running Linux.

The code, however, is a complete mess. This is a learning project and not meant
for anything serious.


How to compile
--------------

To compile, you need either gcc or clang installed and the `pcap` library and
development headers present.
`webscan` uses Linux capibilities so right now it's not portable.

::

   git clone http://github.com/passy/webscan.git
   cd webscan
   cmake .
   make
   # The binary is in bin/webscan now. You could also use make install now.


How to use
----------

::

   webscan -h
   sudo webscan new.rdrei.net


What does not work
------------------

Most things. `webscan` requires root privileges to perform raw socket
operations. It does, however, drop the privileges as soon as possible except for
the raw socket permissions. But I'm pretty sure I left a whole buch of security
wholes open. Currently, it drops to UID/GID 1000 which is hard coded.


What does work
--------------

The uptime detection can be quite accurate, but only for some versions of linux.
Eventually, webscan could get some kind of OS fingerprinting so uptime
calculations work for other OSes as well.
