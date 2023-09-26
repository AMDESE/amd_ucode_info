amd\_ucode\_info.py
===================
amd\_ucode\_info.py provides a means to parse and display information about an
amd-ucode (CPU microcode) container file in the format consumed by the linux
kernel.

Usage
=====
```
$ ./amd_ucode_info.py --help
usage: amd_ucode_info.py [-h] [-e EXTRACT] [-s SPLIT] [-m MERGE] [-v]
                         container_file [container_file ...]

Print information about an amd-ucode container

positional arguments:
  container_file

options:
  -h, --help            show this help message and exit
  -e EXTRACT, --extract EXTRACT
                        Dump each patch in container to the specified
                        directory
  -s SPLIT, --split SPLIT
                        Split out each patch in a separate container to the
                        specified directory
  -m MERGE, --merge MERGE
                        Write a merged container to the specified file
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

Instead of the raw patches, container can also be split out into multiple files,
each containing only a single patch, but still useable by the linux kernel:
```
$ ./amd_ucode_info.py /lib/firmware/amd-ucode/microcode_amd_fam17h.bin -s /tmp/extract-here
Microcode patches in /lib/firmware/amd-ucode/microcode_amd_fam17h.bin:
  Family=0x17 Model=0x01 Stepping=0x02: Patch=0x08001250 Length=3200 bytes
    Patch extracted to /tmp/extract-here/mc_equivid_0x8012_cpuid_0x00800f12_patch_0x08001250.bin
  Family=0x17 Model=0x08 Stepping=0x02: Patch=0x0800820d Length=3200 bytes
    Patch extracted to /tmp/extract-here/mc_equivid_0x8082_cpuid_0x00800f82_patch_0x0800820d.bin
$ ./amd_ucode_info.py /tmp/extract-here/mc_equivid_0x8012_cpuid_0x00800f12_patch_0x08001250.bin
Microcode patches in /tmp/extract-here/mc_equivid_0x8012_cpuid_0x00800f12_patch_0x08001250.bin:
  Family=0x17 Model=0x01 Stepping=0x02: Patch=0x08001250 Length=3200 bytes

```

