import sys
import os
from trex.positions import *
from trex.tokens import *
from grex.operators import *
from grex.alignment import *
import pandas as pd
import tapcap


def generate(pysharkList, threshold1, threshold2):
    count = 0

    #init lists to be used
    tokenList = []
    posList = []

    #init single byte token list
    singleByteTokens = []

    #init prefix and suffix lists
    prefixList = []
    suffixList = []

    print("Mining tokens...")
    posList = track_positions(pysharkList)

    #reverse the packets
    revPack = reverse_packets(pysharkList)

    #make certain reverse tokens and track their (reverse) positions
    #revTokenList = make_tokens(revPack, 1, 1, 1, 2)
    #revPosList = track_positions(revPack)

    prefixList = make_tokens(pysharkList, threshold1, 1, 1, 2)
    suffixList = make_tokens(pysharkList, threshold2, 1, 1, 2)

    prefixes = find_prefixes(pysharkList, prefixList)
    suffixes = find_suffixes(pysharkList, suffixList)

    for item in prefixes:
        if item in suffixes:
            suffixes.remove(item)

    #CHOICE operators, start with the prefix if there is any
    prefix = match_beginning_operator(choice_operator(prefixes))
    if prefix == "^()":
        prefix = ""

    #build suffix
    suffix = match_end_operator(choice_operator(suffixes))
    if suffix == "()$":
        suffix = ""

    #print("Single Byte Tokens Created: ", singleByteTokens)
    print("Prefixes: ", prefix)
    print("Suffixes: ", suffix)

    #remove max length of prefix/suffix from string
    splice_prefix(pysharkList, prefixes)
    splice_suffix(pysharkList, suffixes)

    print("aligning...")
    regex = align(pysharkList)
    regexfinal = removeStars(regex)
    regex_string = ""
    result = ""

    escaped_regex = extraBack(regex_string.join(regexfinal))
    result = prefix + escaped_regex + suffix
    print("Regex: " + str(result))

def main():
    print("RExACtor: A Regular Expression Apriori Constructor")
    preThres = float(input("Prefix frequency threshold (0.0 - 1.0)? "))
    sufThres = float(input("Suffix frequency threshold (0.0 - 1.0)? "))
    filepath = input("File input path (PCAP, PCAPNG, or CSV)? ")
    while not os.path.isfile(filepath):
        print("File not found.")
        filepath = input("File input path (PCAP, PCAPNG, or CSV)? ")

    CSVextension = filepath[len(filepath) - 3:].lower()
    PCAPextension = filepath[len(filepath) - 4:].lower()
    PCAPNGextension = filepath[len(filepath) - 6:].lower()

    if PCAPextension == "pcap" or PCAPNGextension == "pcapng":
        pcap2csv(filepath, "local.csv")
        filepath = "local.csv"
    elif CSVextension != "csv":
        print("Invalid source file provided. Must be .csv, .pcap, or .pcapng.")
        sys.exit()

    colnames=["frame_number", "time", "highest_protocol", "l4_protocol", "text", "src_ip", "src_port", "dst_ip", "dst_port", "len", "ipflags", "tos", "bytes"]
    file = pd.read_csv(filepath, names=colnames, delimiter="|", header=None)
    pysharkList = [i for i in list(file["text"]) if i != '']
    count = 0

    generate(pysharkList, preThres, sufThres)

if __name__ == "__main__":
    main()
