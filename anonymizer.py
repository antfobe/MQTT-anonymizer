import os
import sys
import argparse
import netaddr
import ipaddress
from scapy.utils import PcapReader, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
from scapy.contrib.mqtt import MQTT

parser = argparse.ArgumentParser(description='Extract layer information or anonymize a MQTT pcap file',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--inputfile', type=argparse.FileType('r'),
                    required=True,
                    help='The input pcap file of a MQTT capture')
parser.add_argument('-e', '--extractlayers',
                    action='store_true',
                    help='Outputs the layers identified in the capture for anonymization')
parser.add_argument('-r', '--recalculatechecksums',
                    action='store_true',
                    help='Recalculate IP and TCP checksums')
parser.add_argument('-o', '--outputfile', nargs='?', type=str,
                    help='The output pcap file with the anonymized capture')
parser.add_argument('-b', '--batchsize', type=int,
                    default=1023,
                    help='The number of packets to be processed at a time, larger values consume more memory')
parser.add_argument('-l', '--layers', nargs='+', type=str,
                    help='''
                    list of layers to have the payload removed from the capture,
                    note that selecting a network layer will anonymize the application layer
                         ''')
args = parser.parse_args()

if args.extractlayers == True:
    layers_set = set()
    with PcapReader(args.inputfile.name) as pcap:
        for idx,packet in enumerate(pcap):
            counter = 0
            layer = packet.getlayer(counter)
            while layer.name != 'Raw':
                counter += 1
                layers_set.add(layer.name)
                layer = packet.getlayer(counter)
                if layer is None:
                    break
    print(layers_set)
elif args.outputfile is not None:
    if os.path.exists(args.outputfile):
        os.remove(args.outputfile)
    with PcapReader(args.inputfile.name) as pcap:
        packet_list = []
        mac_dict = {}
        mac_counter = int(netaddr.EUI(0))
        fab_dict = {}
        fab_counter = int(netaddr.EUI(0))
        ip_dict = {}
        ip_counter = int(ipaddress.IPv4Address('0.0.0.0'))
        for idx,packet in enumerate(pcap):
            # anonymize MAC and IP
            if packet.getlayer(0).src[9:17] not in mac_dict:
                mac_dict[packet.getlayer(0).src[9:17]] = mac_counter
                mac_counter += 1
            if packet.getlayer(0).dst[9:17] not in mac_dict:
                mac_dict[packet.getlayer(0).dst[9:17]] = mac_counter
                mac_counter += 1
            if packet.getlayer(0).src[0:8] not in fab_dict:
                fab_dict[packet.getlayer(0).src[0:8]] = fab_counter
                fab_counter += 1
            if packet.getlayer(0).dst[0:8] not in fab_dict:
                fab_dict[packet.getlayer(0).dst[0:8]] = fab_counter
                fab_counter += 1
            packet.getlayer(0).src = netaddr.EUI(fab_dict[packet.getlayer(0).src[0:8]] * int(netaddr.EUI('00:00:01:00:00:00')) +
                                                 mac_dict[packet.getlayer(0).src[9:17]], dialect=netaddr.mac_unix_expanded)
            packet.getlayer(0).dst = netaddr.EUI(fab_dict[packet.getlayer(0).dst[0:8]] * int(netaddr.EUI('00:00:01:00:00:00')) +
                                                 mac_dict[packet.getlayer(0).dst[9:17]], dialect=netaddr.mac_unix_expanded)
            if packet.haslayer("IP"):
                if packet["IP"].src not in ip_dict:
                    ip_dict[packet["IP"].src] = ip_counter
                    ip_counter += 1
                if packet["IP"].dst not in ip_dict:
                    ip_dict[packet["IP"].dst] = ip_counter
                    ip_counter += 1
                packet["IP"].src = ipaddress.IPv4Address(ip_dict[packet["IP"].src])
                packet["IP"].dst = ipaddress.IPv4Address(ip_dict[packet["IP"].dst])
                # remove given layers payloads
                if args.layers is not None:
                    for layer in args.layers:
                        if packet.haslayer(layer) == True:
                            packet[layer].remove_payload()
                            # recalculate checksums
                            if args.recalculatechecksums == True:
                                del packet["IP"].chksum
                                if packet.haslayer("TCP") == True:
                                    del packet["TCP"].chksum
                                packet = packet.__class__(bytes(packet))
            if idx % args.batchsize == 0:
                with PcapWriter(args.outputfile, append=True) as out_pcap:
                    out_pcap.write(packet_list)
                packet_list = []
            else:
                packet_list.append(packet)
        with PcapWriter(args.outputfile, append=True) as out_pcap:
            out_pcap.write(packet_list)
        packet_list = []
