from llm_handler import llm_request

from scapy.all import sniff,AsyncSniffer, IP,TCP,UDP

from collections import defaultdict
from datetime import datetime
import pandas as pd
import time

COOLDOWN = 30
prev_request = defaultdict(float)
sniffer = None

#Uses pandas to read the file and assign it to a variable

df = pd.read_csv("ip_blacklist.csv")
blacklist = set(df['ip'].astype(str))


def alert_handler(data, src_ip, dst_ip):
	global counter
	now = time.time()
	key = tuple(sorted([src_ip, dst_ip]))
	
	last_alert = prev_request.get(key)
	print(last_alert)
	
	if last_alert and (now - last_alert) < COOLDOWN:	
		return
		
	prev_request[key] = now 
	counter =+ 1
	data['counter'] = counter
	llm_request(data)
	return data

#This function handles packet capture and detection
def packet_handler(packet):
	#Checks to ensure that the packets that are capture have an IP address
	if IP in packet:
		src_ip = packet[IP].src
		dst_ip = packet[IP].dst
		#Checks to see if the source or destination IP address is in the blacklist file
		if src_ip in blacklist or dst_ip in blacklist:
			data["timestamp"] = datetime.now().isoformat()
			data["src_ip"] = packet[IP].src
			data["dst_ip"] = packet[IP].dst
			data["protocol"] = packet[IP].proto
			data["alert_type"] = "Reported malicious IP"
			
			#Checks what protocol is being used by the packet
			if TCP in packet:
				data["src_port"] = packet[TCP].sport
				data["dst_port"] = packet[TCP].dport
				data["protocol"] = "TCP"
			elif UDP in packet:
				data["src_port"] = packet[UDP].sport
				data["dst_port"] = packet[UDP].dport
				data["protocol"] = "UDP"
				
			#Executes the alert handler function
			alert_handler(data, src_ip, dst_ip)

#The function to begin the sniff function	
def begin_sniff(shared_data):
	global sniffer
	global data
	data = shared_data
	sniffer = AsyncSniffer(prn = packet_handler ,store = False)
	sniffer.start()

#The function to end the sniff function
def end_sniff():
	global sniffer
	if sniffer:
		sniffer.stop()
