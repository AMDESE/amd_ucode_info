amd\_ucode\_info.py
===================
amd\_ucode\_info.py provides a means to parse and display information about an
amd-ucode (CPU microcode) container file in the format consumed by the linux
kernel.

Usage
=====
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

