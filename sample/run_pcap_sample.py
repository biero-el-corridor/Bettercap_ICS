import argparse
from scapy.all import *
import time

parser = argparse.ArgumentParser()
####if word doe not contain / 

parser.add_argument('-f', '--file' , help='filename or path to the file + filename',type=str)

args = parser.parse_args()

def play_pcap(file_name):
    pkts = rdpcap(file_name)
    for p in pkts:
        sendp(p)
        time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    play_pcap(args.file)
