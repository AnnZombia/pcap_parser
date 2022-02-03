from __future__ import print_function
from ctypes import *
from winpcapy import *
import string
import struct
import sys
import datetime,time

## global variables description --------------------------------------------------------------------------------

source_ports = [] # list of source ports, used to collect unique sessions
outgoing_packets = [] # massive of important properties of outgoing packets
incoming_packets = [] # massive of important properties of incoming packets
wait_counter = 0 # counter of every 5000 packets for informing user about normal (but very slow) data analyzing :)
dns = [] #  massive of important properties of TCP and UPD DNS packets
dns_requests_count = 0 # counter of all dns requests
dns_good_responces_count = 0 # counter for all <No error> responces
j = 0 # counter for outgoing_packets table
l = 0 # counter for incoming_packets table
k = 0 # counter for dns requests table
# probe_ip: this variable is declared in the end of code, it`s the second argument for executing this programm

## <_packet_handler> local variables description ---------------------------------------------------------------

# g = 0 also used for outgoing_packets table
# h = 0 also used for incoming_packets table

## _packet_handler function ------------------------------------------------------------------------------------
# this function is used for every packet processing, it`s called <Callback function>

def _packet_handler(temp,header,packet_data):
    global source_ports
    global outgoing_packets
    global incoming_packets
    global wait_counter
    global probe_ip
    global dns
    global dns_requests_count
    global dns_good_responces_count
    global k
    global l
    global j
    
    wait_counter += 1
    if wait_counter%5000 == 0:
        print ("Please wait, the file is being analyzed..")

## Checking type of Ethernet packet content ------------------------------------------------------------------

    e_c_t = packet_data[12] << 8
    eth_content_type = e_c_t + packet_data[13] # type of Ethernet packet payload, needed for filtering only IP packets
    
## Filtering IP packets and calc its parameters --------------------------------------------------------------

    data_length = header.contents.caplen # header.contents.caplen means whole packet content length in bytes, it`s not a variable, but in future we will need to decrease it
    if eth_content_type == 2048: # 2048 is IPv4 protocol
        packet_data = packet_data[14:data_length] # delete ETHERNET header, it`s always 14 bytes length
        data_length = header.contents.caplen - 14 # length was shortened by 14 bytes because of ethernet header (that is what i was talking about in line 54)
        source_ip = str(packet_data[12])+'.'+str(packet_data[13])+'.'+str(packet_data[14])+'.'+str(packet_data[15]) # source IP address
        destination_ip = str(packet_data[16])+'.'+str(packet_data[17])+'.'+str(packet_data[18])+'.'+str(packet_data[19]) # destination IP address
        ip_header_length = (packet_data[0] & 15) * 4 # calculate IP header length

## Filtering TCP packets and calc its parameters -------------------------------------------------------------
        
        if packet_data[9] == 6: # 6 is TCP protocol
           
            packet_data = packet_data[ip_header_length:header.contents.caplen] # delete IP header 
            data_length -= - ip_header_length # length was shortened because of IP header (that is what i was talking about in line 54)

            s_p = packet_data [0] << 8
            source_port = s_p + packet_data[1] # calculate source port
        
            d_p = packet_data[2] << 8
            destination_port = d_p + packet_data[3] # calculate destination port

            s_n1 = packet_data[4] << 24
            s_n2 = packet_data[5] << 16
            s_n3 = packet_data[6] << 8
            sequence_number = s_n1+s_n2+s_n3+packet_data[7] # calculate absolute sequence number

            tcp_header_length = (packet_data[12] >> 4) * 4 # calculate TCP header length

## Calculate payload ------------------------------------------------------------------------------------------
# sometimes sniffer cuts the packet for storing smaller file. This <real> size stores in header.content.len
# <Formal> packet size is storing in header.content.len, we will need both of them in future
# FYI: payload - it`s the useful packet content (except headers, in our case it`s all except Ethernet, IP and TCP headers)

            captured = sum(packet_data[ip_header_length + 14 + tcp_header_length:]) # calculate summery packet payload

### Limited payload (really captured)

            lim_p_l = header.contents.caplen - ip_header_length - 14 - tcp_header_length
            if captured == 0: tcp_lim_payload_len = 0
            else: tcp_lim_payload_len = lim_p_l

### Unlimited payload (formally captured)
            
            unlim_p_l = header.contents.len - ip_header_length - 14 - tcp_header_length
            if captured == 0: tcp_unlim_payload_len = 0 # i do not why but sometimes payload should not exist, but we can see a few zeros instead.. so we filter it
            else: tcp_unlim_payload_len = unlim_p_l

## Collect TCP DNS packets main table --------------------------------------------------------------------------
##                                    | arrival time (sec) | arrival time (usec) | direction | port | ----------
# Here direction will be 0: if packet is sent from probe to server, and 1: from server to probe

            if source_port == 53 or destination_port == 53: # DNS protocol <always> uses 53 port, but it could be TCP or UDP packet
                if tcp_lim_payload_len >= 4: # we will need next protocol layer - DNS, and we interested only in 4 first bytes
                    flag = packet_data[tcp_header_length+4] & 15 # calculate flag of DNS responce                 
                    if source_port == 53: # means this is a responce
                        dns.append([])  
                        dns[k].extend ([header.contents.ts.tv_sec, header.contents.ts.tv_usec, 1, destination_port])
                        k += 1
                        if flag == 0: # flag 0 means DNS responce with "No error", other flags will mean some problem 
                            dns_good_responces_count += 1
                    elif destination_port == 53: # means this is a request
                        dns.append([])  
                        dns[k].extend ([header.contents.ts.tv_sec, header.contents.ts.tv_usec, 0, source_port])
                        k += 1
                        dns_requests_count += 1  # DNS request has no flag, so we donot check it
                        
## TCP flag masks ---------------------------------------------------------------------------------------------
# we would not use all of them, but i mentioned them FYI

            f = packet_data[12] & 15
            flag = (f + packet_data[13]) # flag of TCP packet
            
            URG = flag & 32
            ACK = flag & 16
            ACK_SYN = flag & 18
            ACK_PSH = flag & 24
            ACK_FIN = flag & 17
            ACK_PSH_FIN = flag & 25
            PSH = flag & 8
            RST = flag & 4
            SYN = flag & 2
            FIN = flag & 1 

## Collect probe -> server packets main table ------------------------------------------------------------------
##    | probe port | arrival time (sec) | arrival time (usec) | flag | sequence number | real payload |---------

            retransmission = 0 # we need to exclude all retransmissions, because they can confuse us
            
            if source_ip == probe_ip:
                if j == 0:
                    outgoing_packets.append([])                    
                    outgoing_packets[j].extend ([source_port, header.contents.ts.tv_sec, header.contents.ts.tv_usec, flag, sequence_number, tcp_unlim_payload_len])
                    j += 1
                else:
                    for g in range (j):
                        if outgoing_packets[g][0] == source_port and outgoing_packets[g][3] == flag and outgoing_packets[g][4] == sequence_number and outgoing_packets[g][5] == tcp_unlim_payload_len and tcp_unlim_payload_len > 0:
# we exclude all packets with 0 payload because it could be ACKs from probe, that could have the same parameters, except ACK number, which is not important for us
                            retransmission = 1
                            break
                        else:
                            retransmission = 0 # if packet is retransmitted - we will save info just about last one
                    if retransmission == 0:
                        outgoing_packets.append([])
                        outgoing_packets[j].extend ([source_port, header.contents.ts.tv_sec, header.contents.ts.tv_usec, flag, sequence_number, tcp_unlim_payload_len])
                        j += 1
                    else:                      
                        outgoing_packets[g][1] = header.contents.ts.tv_sec
                        outgoing_packets[g][2] = header.contents.ts.tv_usec                         
                    
## Collect server -> probe packets main table ------------------------------------------------------------------
##   | server port | arrival time (sec) | arrival time (usec) | flag | sequence number | real payload |---------
            
            if destination_ip == probe_ip:
                if l == 0:
                    incoming_packets.append([])
                    incoming_packets[l].extend ([source_port, header.contents.ts.tv_sec, header.contents.ts.tv_usec, flag, sequence_number, tcp_unlim_payload_len])
                    l += 1
                else:
                    for h in range (l):                   
                        if incoming_packets[h][0] == destination_port and incoming_packets[h][3] == flag and incoming_packets[h][4] == sequence_number and incoming_packets[h][5] == tcp_unlim_payload_len and incoming_packets[h][5] > 0:
                            retransmission = 1
                            break
                        else:
                            retransmission = 0 # if packet is retransmitted - we will save info just about last one
                    if retransmission == 0:                    
                        incoming_packets.append([])
                        incoming_packets[l].extend ([destination_port, header.contents.ts.tv_sec, header.contents.ts.tv_usec, flag, sequence_number, tcp_unlim_payload_len])             
                        l += 1                     
                    else:             
                        incoming_packets[h][1] = header.contents.ts.tv_sec
                        incoming_packets[h][2] = header.contents.ts.tv_usec

## Filtering UDP packets and calc its parameters ---------------------------------------------------------------
        
        elif packet_data[9] == 17: # 17 is UDP protocol


            packet_data = packet_data[ip_header_length:header.contents.caplen] # delete IP header
            data_length -= - ip_header_length # length was shortened because of IP header            
            s_p = packet_data[0] << 8
            source_port = s_p + packet_data[1] # calculate source port
            d_p = packet_data[2] << 8
            destination_port = d_p + packet_data[3] # calculate destination port

            udp_header_length = 8 # standart UDP header length
            
            u_p_l = packet_data[4] << 8
            udp_packet_length = u_p_l + packet_data[5] # calculate UDP packet length (here it`s payload + header)

## Collect DNS UDP packets main table --------------------------------------------------------------------------
##                                    | arrival time (sec) | arrival time (usec) | direction | port | ----------
# Here direction will be 0: from probe to server, 1: from server to probe

            if source_port == 53 or destination_port == 53:
                if udp_packet_length >= 12: # we have to check that all needed bytes exist
                    flag = packet_data[11] & 15 # calculate flag                   
                    if source_port == 53:
                        dns.append([])  
                        dns[k].extend ([header.contents.ts.tv_sec, header.contents.ts.tv_usec, 1, destination_port])
                        k += 1
                        if flag == 0:
                            dns_good_responces_count += 1  # as i said before, flag 0 means "No error", other flags will mean some problem 
                    elif destination_port == 53:
                        dns.append([])  
                        dns[k].extend ([header.contents.ts.tv_sec, header.contents.ts.tv_usec, 0, source_port])
                        k += 1
                        dns_requests_count += 1  # DNS request has no flag, so we donot check it        
                        
## Calculate function -----------------------------------------------------------------------------------------
# here we will calculate all our KPIs

def calculate():

## <calculate> local variables description --------------------------------------------------------------------

    sessions = 0 # counter of all sessions (unique probe ports)
    duration = [] # list of all sessions durations, it`s calculated as time between SYN and last data packet)
    success_ip_sessions = 0 # counter of all successful IP sessions (sessions that have SYN and 1st data packet)
    success_http_sessions = 0  # counter of all successful HTTP sessions (sessions that have SYN and FIN packets) 
    http_session_failure_ratio = 0 # rate of HTTP sessions
    ip_service_failure_ratio = 0 # rate of IP sessions
    dns_duration = [] # list of all DNS resolutions durations, it`s calculated as time between DNS request and DNS responce (does not matter successful or not)
#   f = 0 - used for sessions calculating
#   s = 0 - used for IP sessions rate calculating
#   w = 0 - also used for IP sessions rate calculating
#   o = 0 - used for HTTP sessions rate calculating
#   p = 0 - also used for HTTP sessions rate calculating
#   x = 0 - also used for HTTP sessions rate calculating
#   y = 0 - used for DNS resolving rate calculating
#   r = 0 - also used for DNS resolving rate calculating

## Count number of unique sessions ----------------------------------------------------------------------------
    
    for f in range (j):
        if outgoing_packets[f][3] == 2:
            sessions += 1

## Calculate HTTP IP-Service Access Failure Ratio -------------------------------------------------------------

    for s in range (l):
        if incoming_packets[s][3] == 18: # searching SYN_ACK packets
            frst_dt_pckt_sqns_nmbr = incoming_packets[s][4] + 1 # calculate next packet sequence number (this would be first data packet)
            for w in range (s, l):               
                if frst_dt_pckt_sqns_nmbr == incoming_packets[w][4]: # check if data packet exists
                    if incoming_packets[w][5] > 0:
                        success_ip_sessions += 1
       
## Calculate HTTP Session Failure Ratio and time difference --------------------------------------------------
                        
    for o in range (l):
        if incoming_packets[o][3] == 17 or incoming_packets[o][3] == 25 or incoming_packets[o][3] == 1: # searching ACK_FIN or ACK_FIN_PSH or FIN packets
            for p in range(o,0,-1): # looking for last data packet, it`s somewhere behind FIN packet
                if (incoming_packets[o][0] == incoming_packets[p][0]):
                    last_dt_pckt_sqns_nmbr = incoming_packets[p][4]+incoming_packets[p][5] # calculate previous packet sequence number (this could be last data packet)
# FYI: each subsequent data packet from one side should have sequence number that could be calculated as sequence number of previous packet plus its (previous packet) payload
                    if incoming_packets[o][4] == last_dt_pckt_sqns_nmbr and incoming_packets[p][5] > 0: # check if data packet exists (payload > 0 will exclude ACK packet)
                        success_http_sessions += 1
                        for x in range (j):
                            if outgoing_packets[x][0] == incoming_packets[p][0] and outgoing_packets[x][3] == 2: # looking SYN packet for this session
                                last_data_packet_time = incoming_packets[p][1] + incoming_packets[p][2] / 1000000.0 # calculating time (sec+usec)
                                syn_packet_time = outgoing_packets[x][1] + outgoing_packets[x][2] / 1000000.0
                                duration.append (round(last_data_packet_time-syn_packet_time, 6)) # calculating duration

## Calculate all DNS requests time (successful and not) -------------------------------------------------------

    for y in range (k):
        if dns[y][2] == 0: # filter DNS requests
            for r in range (y,k):
                if dns[r][2] == 1 and dns[y][3] == dns[r][3]: # looking their responces (it should be the same session)
                    request_time = dns[y][0] + dns[y][1] / 1000000.0
                    responce_time = dns[r][0] + dns[r][1] / 1000000.0
                    dns_duration.append (round(responce_time-request_time, 6)) # calculating duration

## Final calculations ----------------------------------------------------------------------------------------

    if sessions != 0:
        ip_service_failure_ratio = round (100 - (success_ip_sessions/sessions)*100, 2)
        http_session_failure_ratio = round (100 - (success_http_sessions/sessions)*100, 2)

        print ("Number of session:                  ", sessions)
        print ("Number of success IP sessions:      ", success_ip_sessions)
        print ("Number of success HTTP sessions:    ", success_http_sessions)
        print ("Failure IP sessions rate:           ", ip_service_failure_ratio, "%")
        print ("Failure HTTP sessions Rate:         ", http_session_failure_ratio, "%")
        
    if len(duration) != 0:
        avg_session_time = round (float(sum(duration))/len(duration), 6)
        min_session_time = round (float(min(duration))/len(duration), 6)
        max_session_time = round (float(max(duration))/len(duration), 6)
        print ("Average successful session time:    ", avg_session_time, "sec")
        print ("Minimum successful session time:    ", min_session_time, "sec")
        print ("Maximum successful session time:    ", max_session_time, "sec")        
    else: print ("\nNo session duration KPI because no successful HTTP session found\n")

    if dns_requests_count > 0:
        dns_failure_ratio = round (100 - (dns_good_responces_count/dns_requests_count)*100, 2)
        avg_resolution_time = round (float(sum(dns_duration))/len(dns_duration), 6)
        min_resolution_time = round (float(min(dns_duration))/len(dns_duration), 6)
        max_resolution_time = round (float(max(dns_duration))/len(dns_duration), 6)
        print ("Number of DNS requests:             ", dns_requests_count)
        print ("Failure DNS resolution Rate:        ", dns_failure_ratio, "%")
        print ("Average resolution time:            ", avg_resolution_time, "sec")
        print ("Minimum resolution time:            ", min_resolution_time, "sec")
        print ("Maximum resolution time:            ", max_resolution_time, "sec")    
    else: print ("\nNo DNS resolving duration KPI because no DNS request found\n")

## C callback function interpretation ---------------------------------------------------------------------------------
    
PHAND = CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))
packet_handler=PHAND(_packet_handler)

## Executing options -----------------------------------------------------------------------------------------

processor = pcap_t
errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

if len(sys.argv) == 1:
    print ("\nusage: %s filename probe_ip_address\n" % sys.argv[0])
    sys.exit(-1)
elif len(sys.argv) == 2:
    print ("\nusage: %s %s ProbeIP\n" % (sys.argv[0], sys.argv[1]))
    sys.exit(-1)

probe_ip = sys.argv[2] 
file_name = sys.argv[1].encode('utf-8')

## Open a savefile in the tcpdump/libpcap format to read packets ---------------------------------------------

processor = pcap_open_offline(file_name,errbuf)
if not bool(processor):
    print ("\nUnable to open the file %s.\n" % sys.argv[1])
    sys.exit(-1)

## Read and dispatch packets until EOF is reached ------------------------------------------------------------
    
pcap_loop(processor, 0, packet_handler, None)
calculate()
pcap_close(processor)
sys.exit(0)

## That's all folks)
