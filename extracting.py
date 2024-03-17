from readelf3 import *
import sys
import subprocess
from subprocess import call
import pandas as pd
import csv
import os

features = []
headers = []

section_list_size = 0


def prepare_headers():
    headers.extend(["Name", "Identification", "MachineType", "ELFVersion", "EntryPointAddress", "ProgramHeaderOffset",
                    "SectionHeaderOffset", "Flags", "HeaderSize", "SizeProgramHeader", "EntriesProgram",
                    "SizeSectionHeader", "EntriesSection", "StringTableIndex"])
    print(len(headers))
    sections_list = [".text", ".bss", ".comment", ".data", ".data1", ".debug", ".dynamic", ".dynstr", ".dynsym",
                     ".fini", ".hash", ".gnu.hash", ".init", ".got", ".interp", ".line", ".note", ".plt", ".rodata",
                     "rodata1", ".shstrtab", ".strtab", ".symtab", ".sdata", ".sbss", ".lit8", ".gptab", ".conflict",
                     ".tdesc", ".lit4", ".reginfo", ".liblist", ".rel.dyn", ".rel.plt", ".got.plt"]

    suffix_list = ["_type", "_flags", "_size", "_entsize", "_table_index_link", "_info", "_alignment"]
    section_list_size = len(sections_list)
    for i in sections_list:
        a = []
        for j in suffix_list:
            a.append(i + j)
        headers.extend(a)

    print(len(headers))


def input_file(file):
    features.append(file)
    print("Input file: %s" % file)
    with open(file, 'rb') as f:
        try:
            elf = ReadElf(f, sys.stdout)
            return elf
        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)

    return None


def elf_headers(elf):
    identification, file_class, data, version, abi, abi_version, type_file, machine, version, entry_point_address, start_program_headers, start_section_headers, flags, header_size, size_program_header, num_program_header, size_section_header, num_section_header, str_table_ind = elf.display_file_header()
    features.extend(
        [identification, machine, version, entry_point_address, start_program_headers, start_section_headers, flags,
         header_size, size_program_header, num_program_header, size_section_header, num_section_header, str_table_ind])


def section_headers(file):
    # elf = input_file()
    sections_data_list = process(file)[0][1:]
    features_new = [""] * 245
    features.extend(features_new)
    for i, section_data in enumerate(sections_data_list):
        try:
            ind = headers.index(section_data[0] + "_type")
            for j, value in enumerate(section_data[1:]):
                features[ind + j] = value
        except:
            continue
    return dict(zip(headers, features))

if __name__ == "__main__":
    file = "basic.x86_64"
    prepare_headers()
    elf = input_file(file)
    elf_headers(elf)
    hf = section_headers(file)
    for header, feature in hf.items():
        print(f'{header} : {feature}')


