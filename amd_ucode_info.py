#!/usr/bin/python3
# SPDX-License-Identifier: MIT License
# Copyright (C) 2020 Advanced Micro Devices, Inc. 

"""
Parse an amd-ucode container file and print the family, model, stepping number,
and patch level for each patch in the file. The --extract option will dump the
raw microcode patches to a provided directory.
"""

import argparse
import sys
import os

EQ_TABLE_ENTRY_SIZE = 16
EQ_TABLE_LEN_OFFSET = 8
EQ_TABLE_OFFSET = 12

VERBOSE_DEBUG = 2


def read_int32(ucode_file):
    """ Read four bytes of binary data and return as a 32 bit int """
    return int.from_bytes(ucode_file.read(4), 'little')

def read_int16(ucode_file):
    """ Read two bytes of binary data and return as a 16 bit int """
    return int.from_bytes(ucode_file.read(2), 'little')

def read_int8(ucode_file):
    """ Read one byte of binary data and return as a 8 bit int """
    return int.from_bytes(ucode_file.read(1), 'little')

def parse_equiv_table(opts, ucode_file, eq_table_len):
    """
    Read equivalence table and return a list of the equivalence ids contained
    """
    table = {}

    table_item = EQ_TABLE_OFFSET
    table_stop = EQ_TABLE_OFFSET + eq_table_len

    while table_item < table_stop:
        ucode_file.seek(table_item, 0)

        """
        struct equiv_cpu_entry {
            u32 installed_cpu;
            u32 fixed_errata_mask;
            u32 fixed_errata_compare;
            u16 equiv_cpu;
            u16 res;
        } __packed;
        """
        cpu_id = read_int32(ucode_file)
        errata_mask = read_int32(ucode_file)
        errata_compare = read_int32(ucode_file)
        equiv_id = read_int16(ucode_file)
        res = read_int16(ucode_file)

        if equiv_id != 0:
            table[equiv_id] = cpu_id

        if opts.verbose >= VERBOSE_DEBUG:
            print((" [equiv entry@%#010x: cpuid %#010x, equiv id %#06x, " +
                   "errata mask %#010x, errata compare %#010x, res %#06x]") %
                  (table_item, cpu_id, equiv_id, errata_mask, errata_compare,
                   res))

        table_item += EQ_TABLE_ENTRY_SIZE

    return table

def extract_patch(opts, patch_start, patch_length, ucode_file, ucode_level):
    """
    Extract raw microcode patch starting at patch_start to the directory
    provided by the -o option or the current directory if not specified.
    Directory will be created if it doesn't already exist.
    """
    cwd = os.getcwd()

    if not os.path.exists(opts.extract):
        os.makedirs(opts.extract)

    os.chdir(opts.extract)

    ucode_file.seek(patch_start, 0)
    out_file_name = "mc_patch_0%x.bin" % (ucode_level)
    out_file = open(out_file_name, "wb")
    out_file.write(ucode_file.read(patch_length))
    out_file.close()

    print("    Patch extracted to %s/%s" % (os.getcwd(), out_file_name))

    os.chdir(cwd)

def parse_ucode_file(opts, path):
    """
    Scan through microcode container file printing the microcode patch level
    for each model contained in the file.
    """
    with open(path, "rb") as ucode_file:
        print("Microcode patches in %s:" % path)

        # Seek to end of file to determine file size
        ucode_file.seek(0, 2)
        end_of_file = ucode_file.tell()

        # Check magic number
        ucode_file.seek(0, 0)
        if ucode_file.read(4) != b'DMA\x00':
            print("ERROR: Missing magic number at beginning of container")
            return

        # Read the equivalence table length
        ucode_file.seek(EQ_TABLE_LEN_OFFSET, 0)
        eq_table_len = read_int32(ucode_file)

        ids = parse_equiv_table(opts, ucode_file, eq_table_len)

        cursor = EQ_TABLE_OFFSET + eq_table_len
        while cursor < end_of_file:
            # Seek to the start of the patch information
            ucode_file.seek(cursor, 0)

            patch_start = cursor + 8

            patch_type = read_int32(ucode_file)
            if patch_type != 1:
                print("Invalid patch identifier: %#010x" % (patch_type))
                break

            patch_length = read_int32(ucode_file)

            """
            struct microcode_header_amd {
                u32 data_code;
                u32 patch_id;
                u16 mc_patch_data_id;
                u8  mc_patch_data_len;
                u8  init_flag;
                u32 mc_patch_data_checksum;
                u32 nb_dev_id;
                u32 sb_dev_id;
                u16 processor_rev_id;
                u8  nb_rev_id;
                u8  sb_rev_id;
                u8  bios_api_rev;
                u8  reserved1[3];
                u32 match_reg[8];
            } __packed;
            """
            data_code = read_int32(ucode_file)
            ucode_level = read_int32(ucode_file)
            mc_patch_data_id = read_int16(ucode_file)
            mc_patch_data_len = read_int8(ucode_file)
            init_flag = read_int8(ucode_file)
            mc_patch_data_checksum = read_int32(ucode_file)
            nb_dev_id = read_int32(ucode_file)
            sb_dev_id = read_int32(ucode_file)
            equiv_id = read_int16(ucode_file)
            nb_rev_id = read_int8(ucode_file)
            sb_rev_id = read_int8(ucode_file)
            bios_api_rev = read_int8(ucode_file)
            reserved1 = [read_int8(ucode_file) for _ in range(3)]
            match_reg = [read_int32(ucode_file) for _ in range(8)]

            if opts.verbose:
                add_info = " Start=%u bytes Date=%04x-%02x-%02x Equiv_id=%#06x" % \
                           (patch_start, data_code & 0xffff, data_code >> 24,
                            (data_code >> 16) & 0xff, equiv_id)
            else:
                add_info = ""

            if equiv_id not in ids:
                print("Patch equivalence id not present in equivalence table (%#06x)"
                      % (equiv_id))

                cursor = cursor + patch_length + 8
                continue

            cpu_id = ids[equiv_id]

            # The cpu_id is the equivalent to CPUID_Fn00000001_EAX
            family = (cpu_id >> 8) & 0xf
            family += (cpu_id >> 20) & 0xff

            model = (cpu_id >> 4) & 0xf
            model |= (cpu_id >> 12) & 0xf0

            stepping = cpu_id & 0xf

            print("  Family=%#04x Model=%#04x Stepping=%#04x: Patch=%#010x Length=%u bytes%s"
                  % (family, model, stepping, ucode_level, patch_length, add_info))

            if opts.verbose >= VERBOSE_DEBUG:
                print(("   [data_code=%#010x, mc_patch_data_id=%#06x, " +
                       "mc_patch_data_len=%#04x, init_flag=%#04x, " +
                       "mc_patch_data_checksum=%#010x]") %
                      (data_code, mc_patch_data_id, mc_patch_data_len,
                       init_flag, mc_patch_data_checksum))
                print(("   [nb_dev_id=%#010x, sb_dev_id=%#010x, " +
                       "nb_rev_id=%#04x, sb_rev_id=%#04x, " +
                       "bios_api_rev=%#04x, reserved=[%#04x, %#04x, %#04x]]") %
                      (nb_dev_id, sb_dev_id, nb_rev_id, sb_rev_id,
                       bios_api_rev, reserved1[0], reserved1[1], reserved1[2]))
                print("   [match_reg=[%s]]" %
                      ", ".join(["%#010x" % x for x in match_reg]))

            if opts.extract:
                extract_patch(opts, patch_start, patch_length, ucode_file,
                              ucode_level)

            cursor = cursor + patch_length + 8

def parse_ucode_files(opts):
    for f in opts.container_file:
        parse_ucode_file(opts, f)

def parse_options():
    """ Parse options """
    parser = argparse.ArgumentParser(description="Print information about an amd-ucode container")
    parser.add_argument("container_file", nargs='+')
    parser.add_argument("-e", "--extract",
                        help="Dump each patch in container to the specified directory")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity level: provide once " +
                             "to see additional information about patches, " +
                             "twice to see all the information available")
    opts = parser.parse_args()

    for f in opts.container_file:
        if not os.path.isfile(f):
            parser.print_help()
            print()
            print("ERROR: Container file \"%s\" does not exist" % f)
            sys.exit()

    return opts

def main():
    """ main """
    opts = parse_options()

    parse_ucode_files(opts)

if __name__ == "__main__":
    main()
