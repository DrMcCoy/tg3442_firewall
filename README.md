tg3442_firewall README
======================

tg3442_firewall is a small Python program that enable and disable the firewall
on the Arris TG3442 DOCSIS router, by logging in through the web frontend.

tg3442_firewall is released under the terms of the 1-clause BSD license.
See tg3442_firewall.py for details.

Dependencies
------------

BeautifulSoup
binascii
hashlib
json
os
PyCryptodome (see "PyCrypto vs PyCryptodome(x)" below)
re
requests
sys

PyCrypto vs PyCryptodome(x)
---------------------------

tg3442_firewall requires the AES CCM crypto mode, which is not available in
the last released version of the stock PyCrypto module. Moreover, PyCrypto
has been abandoned. The drop-in replacement is PyCryptodome, which contains
that required AES mode.

PyCryptodome comes in two flavours: one that installs into the Crypto
namespace (thus providing a drop-in replacement) and one that install
into the Cryptodome namespace. The latter flavour is commonly referred to
as PyCryptodomex.

Depending on your Python distribution and whether you need the orginal
PyCrypto module, you may need to install either pycryptodome or
pycryptodomex, via pip or an external package manager.
