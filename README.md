
# Protocol N0 .. Protocol 765+ - Netty Handshake (oldid=4899)
# Protocol P33 .. Protocol P80 - New Handshake (oldid=997)
# Protocol P0 .. Protocol P32 - Old Handshake (oldid=932)
- Need to fake the connection hash and nullify the handshake from the server.

# Protocol P39 .. Protocol P80 - New List Ping with Magic Number 0x01
# Protocol P0 .. P39 - Old List ping 0xFE no content.

# Protocol P0 .. P10 uses MUTF-8
# Protocol P11 .. P80 uses UCS-2
Possible im-pass, as there is no way to tell protocol before sending MUTF-8/UCS-2 String Handshake Response.
- Check whether the handshake sent to me is in UCS-2 or MUTF-8 format!!!
