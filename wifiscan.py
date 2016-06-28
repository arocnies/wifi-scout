__author__ = 'aaron'

from scapy.all import *

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

KNOWN_SOURCES = []

def log_packet(p):

    signal_strength = "Unknown"
    if p.notdecoded is not None:
        signal_strength = -(256 - ord(p.notdecoded[-4:-3]))

    target = p.addr3
    source = p.addr2
    ssid = p.getlayer(Dot11ProbeReq).info
    rssi = signal_strength

    if source not in KNOWN_SOURCES:
        KNOWN_SOURCES.append(source)
        print 'New source: target = %s | source = %s | SSID = %s | RSSi = %d' % (target, source, ssid, rssi)

    # print "Packet: target = %s | source = %s | SSID = %s | RSSi = %d" % (target, source, ssid, rssi)


def handle_packet(p):
    if p.haslayer(Dot11):
        if p.type == PROBE_REQUEST_TYPE and p.subtype == PROBE_REQUEST_SUBTYPE:
            log_packet(p)


def main():
    from datetime import datetime

    print "[%s] Starting scan " % datetime.now()
    print "Scanning for:\n"
    sniff(iface=sys.argv[1], prn=handle_packet)


if __name__ == '__main__':
    main()