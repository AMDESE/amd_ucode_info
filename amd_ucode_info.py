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

from collections import namedtuple
from collections import OrderedDict

EQ_TABLE_ENTRY_SIZE = 16
EQ_TABLE_LEN_OFFSET = 8
EQ_TABLE_OFFSET = 12
EQ_TABLE_TYPE = 0
PATCH_TYPE = 1

VERBOSE_DEBUG = 2

FMS = namedtuple("FMS", ("family", "model", "stepping"))
EquivTableEntry = namedtuple("EquivTableEntry", ("cpuid", "equiv_id", "data", "offset"))
PatchEntry = namedtuple("PatchEntry", ("file", "offset", "size", "equiv_id", "level"))


def read_int32(ucode_file):
    """ Read four bytes of binary data and return as a 32 bit int """
    return int.from_bytes(ucode_file.read(4), 'little')

def read_int16(ucode_file):
    """ Read two bytes of binary data and return as a 16 bit int """
    return int.from_bytes(ucode_file.read(2), 'little')

def read_int8(ucode_file):
    """ Read one byte of binary data and return as a 8 bit int """
    return int.from_bytes(ucode_file.read(1), 'little')

def cpuid2fms(cpu_id):
    family = (cpu_id >> 8) & 0xf
    family += (cpu_id >> 20) & 0xff

    model = (cpu_id >> 4) & 0xf
    model |= (cpu_id >> 12) & 0xf0

    stepping = cpu_id & 0xf

    return FMS(family, model, stepping)

def fms2str(fms):
    return "Family=%#04x Model=%#04x Stepping=%#04x" % \
           (fms.family, fms.model, fms.stepping)

def parse_equiv_table(opts, ucode_file, start_offset, eq_table_len):
    """
    Read equivalence table and return a list of the equivalence ids contained
    """
    table = {}
    raw_table = []
    # For sanity check only
    cpuid_map = {}

    table_item = start_offset + EQ_TABLE_OFFSET
    table_stop = start_offset + EQ_TABLE_OFFSET + eq_table_len

    while table_item < table_stop:
        ucode_file.seek(table_item, 0)
        data = ucode_file.read(EQ_TABLE_ENTRY_SIZE)
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
            if equiv_id not in table:
                table[equiv_id] = OrderedDict()

            if cpu_id in table[equiv_id]:
                print(("WARNING: Duplicate CPUID %#010x (%s) " +
                       "in the equivalence table for equiv_id %#06x ") %
                      (cpu_id, fms2str(cpuid2fms(cpu_id)), equiv_id),
                      file=sys.stderr)

            if cpu_id in cpuid_map:
                if equiv_id != cpuid_map[cpu_id]:
                    print(("WARNING: Different equiv_id's (%#06x and %#06x) " +
                           "are present in the equivalence table for CPUID " +
                           "%#010x (%s)") %
                          (equiv_id, cpuid_map[cpu_id], cpu_id,
                           fms2str(cpuid2fms(cpu_id))), file=sys.stderr)
            else:
                cpuid_map[cpu_id] = equiv_id

            entry = EquivTableEntry(cpu_id, equiv_id, data, table_item)
            table[equiv_id][cpu_id] = entry
            raw_table.append(entry)

        if opts.verbose >= VERBOSE_DEBUG:
            print((" [equiv entry@%#010x: cpuid %#010x, equiv id %#06x, " +
                   "errata mask %#010x, errata compare %#010x, res %#06x]") %
                  (table_item, cpu_id, equiv_id, errata_mask, errata_compare,
                   res))

        table_item += EQ_TABLE_ENTRY_SIZE

    return (table, raw_table)

def extract_patch(opts, out_dir, ucode_file, patch, equiv_table=None):
    """
    Extract patch (along with the respective headers and equivalence table
    entries if equiv_table is provided) from ucode_file starting at patch.start
    to a file inside out_dir.  Directory will be created if it doesn't already
    exist.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_dir: directory inside which the output file is stored
    @type out_dir: str
    @param ucode_file: file object to read the patch from
    @type ucode_file: io.BufferedIOBase
    @param patch: the patch to write out
    @type patch: PatchEntry
    @param equiv_table: if provided, a valid container file is created that also
                        includes entries relevant to the patch's equiv_id
    @type equiv_table: dict
    """
    cwd = os.getcwd()

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    os.chdir(out_dir)

    if equiv_table is None:
        # Raw patch
        out_file_name = "mc_patch_0%x.bin" % patch.level
    else:
        out_file_name = "mc_equivid_%#06x" % patch.equiv_id
        for cpuid in equiv_table[patch.equiv_id]:
            out_file_name += '_cpuid_%#010x' % cpuid
        out_file_name += "_patch_%#010x.bin" % patch.level

    out_path = "%s/%s" % (os.getcwd(), out_file_name)
    out_file = open(out_file_name, "wb")

    os.chdir(cwd)

    if equiv_table is not None:
        cpuids = equiv_table[patch.equiv_id].values() if patch.equiv_id in equiv_table else []
    else:
        cpuids = None

    write_mc(opts, out_file, [patch], ucode_file, cpuids)

    out_file.close()

    print("    Patch extracted to %s" % out_path)

def merge_mc(opts, out_path, table, patches):
    """
    Generate a merged container out of the provided table and patches and write
    it to out_path.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_path: path to write out the generated container to
    @type out_path: str
    @param table: a list of equivalence table entries to accompany the patches
    @type table: list(EquivTableEntry)
    @param patches: a list of patches to write out
    @type patches: list(PatchEntry)
    """
    # Do some sanity checks, but only warn about the issues
    equivid_map = {}
    cpuid_map = {}

    for entry in table:
        if entry.equiv_id not in equivid_map:
            equivid_map[entry.equiv_id] = dict()

        if entry.cpuid in equivid_map[entry.equiv_id]:
            print(("WARNING: Duplicate CPUID %#010x (%s) in the equivalence " +
                   "table for equiv_id %#06x ") %
                  (entry.cpuid, fms2str(cpuid2fms(entry.cpuid)),
                   entry.equiv_id), file=sys.stderr)
        else:
            equivid_map[entry.equiv_id][entry.cpuid] = entry

        if entry.cpuid in cpuid_map:
            if entry.equiv_id != cpuid_map[entry.cpuid]:
                print(("WARNING: Different equiv_id's (%#06x and %#06x) " +
                       "are present in the equivalence table for CPUID " +
                       "%#010x (%s)") %
                      (entry.equiv_id, cpuid_map[entry.cpuid], entry.cpuid,
                       fms2str(cpuid2fms(entry.cpuid))), file=sys.stderr)
            else:
                cpuid_map[entry.cpuid] = entry.equiv_id

    with open(out_path, "wb") as out_file:
        write_mc(opts, out_file, patches, equiv_table=table)

        print("Microcode written to %s" % out_path)

def write_mc(opts, out_file, patches, ucode_file=None, equiv_table=None):
    """
    Writes microcode data from patches to out_file.  If equiv_table is provided,
    a valid container file is generated, that also includes a container header,
    the equivalence table, and patch headers.

    @param opts: options, as returned by ArgumentParser.parse_args()
    @type opts: argparse.Namespace
    @param out_file: file object to write the data to
    @type out_file: io.BufferedIOBase
    @param patches: an array of patchesto write out
    @type patches: list(PatchEntry)
    @param ucode_file: file object to read the patch from;
                       if None is provided, a file with path specified
                       in PatchEntry.file is opened instead  (default: None)
    @type ucode_file: io.BufferedIOBase
    @param equiv_table: if provided, a valid container file is created that also
                        includes all the necessary headers and entries provided
                        in equiv_table (default: None)
    @type equiv_table: list(EquivTableEntry)
    """
    if equiv_table is not None:
        # Container header
        out_file.write(b'DMA\x00')

        # Equivalence table header
        out_file.write(EQ_TABLE_TYPE.to_bytes(4, 'little'))
        table_size = EQ_TABLE_ENTRY_SIZE * (len(equiv_table) + 1)
        out_file.write(table_size.to_bytes(4, 'little'))

        # Equivalence table
        for cpuid in equiv_table:
            out_file.write(cpuid.data)

        out_file.write(b'\0' * EQ_TABLE_ENTRY_SIZE)

    for patch in patches:
        # Patch header
        if equiv_table is not None:
            out_file.write(PATCH_TYPE.to_bytes(4, 'little'))
            out_file.write(patch.size.to_bytes(4, 'little'))

        if ucode_file is None:
            in_file = open(patch.file, "rb")
        else:
            in_file = ucode_file

        in_file.seek(patch.offset, 0)
        out_file.write(in_file.read(patch.size))

        if ucode_file is None:
            in_file.close()

def parse_ucode_file(opts, path, start_offset):
    """
    Scan through microcode container file printing the microcode patch level
    for each model contained in the file.
    """
    table = None
    patches = []

    with open(path, "rb") as ucode_file:
        print("Microcode patches in %s%s:" %
              (path, "+%#x" % start_offset if start_offset else ""))

        # Seek to end of file to determine file size
        ucode_file.seek(0, 2)
        end_of_file = ucode_file.tell()

        # Check magic number
        ucode_file.seek(start_offset, 0)
        if ucode_file.read(4) != b'DMA\x00':
            print("ERROR: Missing magic number at beginning of container",
                  file=sys.stderr)
            return (None, None, None)

        # Check the equivalence table type
        eq_table_type = read_int32(ucode_file)
        if eq_table_type != EQ_TABLE_TYPE:
            print("ERROR: Invalid equivalence table identifier: %#010x" %
                  eq_table_type, file=sys.stderr)
            return (None, None, None)

        # Read the equivalence table length
        eq_table_len = read_int32(ucode_file)

        ids, table = parse_equiv_table(opts, ucode_file, start_offset, eq_table_len)

        cursor = start_offset + EQ_TABLE_OFFSET + eq_table_len
        while cursor < end_of_file:
            # Seek to the start of the patch information
            ucode_file.seek(cursor, 0)

            patch_start = cursor + 8

            patch_type_bytes = ucode_file.read(4)
            # Beginning of a new container
            if patch_type_bytes == b'DMA\x00':
                return (cursor, table, patches)
            patch_type = int.from_bytes(patch_type_bytes, 'little')
            if patch_type != PATCH_TYPE:
                print("Invalid patch identifier: %#010x" % (patch_type),
                      file=sys.stderr)
                return (None, table, patches)

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
                      % (equiv_id), file=sys.stderr)
                print(("  Family=???? Model=???? Stepping=????: " +
                       "Patch=%#010x Length=%u bytes%s")
                      % (ucode_level, patch_length, add_info))
            else:
                # The cpu_id is the equivalent to CPUID_Fn00000001_EAX
                for cpuid in ids[equiv_id]:
                    print("  %s: Patch=%#010x Length=%u bytes%s"
                          % (fms2str(cpuid2fms(cpuid)), ucode_level,
                             patch_length, add_info))

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

            patch = PatchEntry(path, patch_start, patch_length, equiv_id, ucode_level)
            patches.append(patch)

            if opts.extract:
                extract_patch(opts, opts.extract, ucode_file, patch)

            if opts.split:
                extract_patch(opts, opts.split, ucode_file, patch, ids)

            cursor = cursor + patch_length + 8

    return (None, table, patches)

def parse_ucode_files(opts):
    all_tables = []
    all_patches = []

    for f in opts.container_file:
        offset = 0
        while offset is not None:
            offset, table, patches = parse_ucode_file(opts, f, offset)
            if opts.merge:
                if table is not None:
                    all_tables += table
                if patches is not None:
                    all_patches += patches

    if opts.merge:
        merge_mc(opts, opts.merge, all_tables, all_patches)

def parse_options():
    """ Parse options """
    parser = argparse.ArgumentParser(description="Print information about an amd-ucode container")
    parser.add_argument("container_file", nargs='+')
    parser.add_argument("-e", "--extract",
                        help="Dump each patch in container to the specified directory")
    parser.add_argument("-s", "--split",
                        help="Split out each patch in a separate container to the specified directory")
    parser.add_argument("-m", "--merge",
                        help="Write a merged container to the specified file")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity level: provide once " +
                             "to see additional information about patches, " +
                             "twice to see all the information available")
    opts = parser.parse_args()

    for f in opts.container_file:
        if not os.path.isfile(f):
            parser.print_help(file=sys.stderr)
            print(file=sys.stderr)
            print("ERROR: Container file \"%s\" does not exist" % f,
                  file=sys.stderr)
            sys.exit()

    return opts

def main():
    """ main """
    opts = parse_options()

    parse_ucode_files(opts)

if __name__ == "__main__":
    main()
