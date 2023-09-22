amd\_ucode\_info.py
===================
amd\_ucode\_info.py provides a means to parse and display information about an
amd-ucode (CPU microcode) container file in the format consumed by the linux
kernel.

Usage
=====
```
$ ./amd_ucode_info.py --help
usage: amd_ucode_info.py [-h] [-e EXTRACT] [-v]
                         container_file [container_file ...]

Print information about an amd-ucode container

positional arguments:
  container_file

options:
  -h, --help            show this help message and exit
  -e EXTRACT, --extract EXTRACT
                        Dump each patch in container to the specified
                        directory
  -v, --verbose         Increase output verbosity level: provide once to see
                        additional information about patches, twice to see all
                        the information available
```

To print information about a container file, pass the path to the container
file as a positional parameter to the amd\_ucode\_info.py script as shown below.
```
# ./amd_ucode_info.py /lib/firmware/amd-ucode/microcode_amd_fam17h.bin
Microcode patches in /lib/firmware/amd-ucode/microcode_amd_fam17h.bin:
  Family=0x17 Model=0x01 Stepping=0x02: Patch=0x08001250 Length=3200 bytes
  Family=0x17 Model=0x08 Stepping=0x02: Patch=0x0800820d Length=3200 bytes
```

The raw patches may also be extracted from the container by using the --extract
or the -e option. When using this option, contained patches will be extracted to
the specified directory.
```
# ./amd_ucode_info.py /lib/firmware/amd-ucode/microcode_amd_fam17h.bin -e /tmp/extract-here
Microcode patches in /lib/firmware/amd-ucode/microcode_amd_fam17h.bin:
  Family=0x17 Model=0x01 Stepping=0x02: Patch=0x08001250 Length=3200 bytes
    Patch extracted to /tmp/extract-here/mc_patch_08001250.bin
  Family=0x17 Model=0x08 Stepping=0x02: Patch=0x0800820d Length=3200 bytes
    Patch extracted to /tmp/extract-here/mc_patch_0800820d.bin
```

