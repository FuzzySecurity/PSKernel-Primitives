# Ntoskrnl ROP Dumps

ROP dumps for various x64 versions of ntoskrnl. Useful for reference, but also as a base for helper functions to stage bitmaps or disable SMEP.

It remains to be seen how useful this will be, it may be better to narrow down the location of a gadget based on exports and have a function to dynamically extract the address at runtime. Alternatively, it may be possible to read in the entire PE as a byte array and look for patterns.. Feedback welcome!

### Index

| Version | Type | File Name |
| ------------- |:-------------:| -----:|
| Windows 8.0 | Professional | 80_6-2-9200-16461_ntoskrnl |
| Windows 8.1 | Home | 81_6-3-9600-16384_ntoskrnl |
| Windows 10 (v1511) | Professional | 10_1511_10586-494_ntoskrnl |
| Windows 10 (v1607) | Professional | 10_1607_14393-693_ntoskrnl |
| Windows 10 (v1703) | Enterprise | 10_1703_15063-138_ntoskrnl |
| Windows 10 (v1703) | Professional | 10_1703_15063-296_ntoskrnl |
