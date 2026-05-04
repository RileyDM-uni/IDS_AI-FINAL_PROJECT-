from tkinter import *
import tkinter as tk
from monitoring import *

status = False


#This function refreshes the UI so that new data can be updated
def refresh():
	try:
		data = shared_data
		timestamp.set(data.get('timestamp',''))
		src_ip.set(data.get('src_ip', ''))
		dst_ip.set(data.get('dst_ip', ''))
		src_port.set(data.get('src_port', ''))
		dst_port.set(data.get('dst_port', ''))
		protocol.set(data.get('protocol', ''))
		alert_type.set(data.get('alert_type', ''))
		counter.set(data.get('counter',0))
		report.set(data.get('report',''))
		
	except Exception as e:
		print("Refresh errors:", e)
	root.after(500, refresh)

#This function handles enabling and disabling the system
def toggle():
	global status
	
	if not status:
		begin_sniff(shared_data)
		btn1.config(text="Disable IDS")
		status = True
		print("IDS started")
	else:
		end_sniff()
		btn1.config(text="Enable IDS")
		status = False
		print("IDS ended")

#This function uses Tkinter to display the UI
def ui(initial_data):
	global btn1
	global root
	global timestamp,src_ip,dst_ip,protocol,src_port,dst_port,alert_type
	global counter
	global report
	
	data = initial_data
	
	root = Tk()

	root.geometry("800x600")
	root.config(bg= 'lightblue')
	
	root.grid_rowconfigure(0, weight=0)
	root.grid_rowconfigure(1, weight=0)
	root.grid_rowconfigure(2, weight=1)
	root.grid_rowconfigure(3, weight=3)
	root.grid_columnconfigure(0, weight=1)
	root.grid_columnconfigure(1, weight=1)
	
	heading = Label(root, text = "Intrusion detection system (IDS)", fg = '#36454F',bg = 'lightblue', font = ('Courier new',16))
	heading.grid(row = 0, column = 0, columnspan = 2)

	section1 = tk.Frame(root, bg = 'White')
	section2 = tk.Frame(root, bg = '#5c5c5c')
	section3 = tk.Frame(root, bg = '#5c5c5c', width = 300, height = 500)
	section4 = tk.Frame(root, bg = '#5c5c5c')
	
	section1.grid(row = 1, column = 0, columnspan =2)
	section2.grid(row = 2, column = 0,sticky = 'ew, n',padx = 20,pady = 20)
	section3.grid(row = 2, column = 1,sticky = 'ew, n',padx = 20,pady = 20, rowspan = 3)
	section4.grid(row = 3, column = 0,sticky = 'n')

	section2.pack_propagate(False)
	section3.pack_propagate(False)
	section4.pack_propagate(False)
	
	btn1 = Button(section1, text = "Enable IDS",command = toggle, bg = '#5c5c5c', foreground = 'White', font = ('Courier new', 12), width = 70)	
	btn1.pack()

	section2.grid_rowconfigure(0, weight=0)
	section2.grid_rowconfigure(1, weight=0)
	section2.grid_rowconfigure(2, weight=1)
	section2.grid_rowconfigure(3, weight=1)
	section2.grid_rowconfigure(4, weight=1)
	section2.grid_rowconfigure(5, weight=1)
	section2.grid_rowconfigure(6, weight=1)
	section2.grid_rowconfigure(7, weight=1)
	section2.grid_columnconfigure(0, weight=1)
	section2.grid_columnconfigure(1, weight=1)
	
	subheading1 = Label(section2, text = "Packet Overview",bg ='#5c5c5c',foreground = "White",font = ('Courier new', 12,'bold'), padx = 10, pady = 5)
	subheading1.grid(row =0, column = 0, sticky = 'w')
	
	timestamp = tk.StringVar(value=data["timestamp"])
	src_ip = tk.StringVar(value=data["src_ip"])
	dst_ip = tk.StringVar(value=data["dst_ip"])
	src_port = tk.StringVar(value=data["src_port"])
	dst_port = tk.StringVar(value=data["dst_port"])
	protocol = tk.StringVar(value=data["protocol"])
	alert_type = tk.StringVar(value=data["alert_type"])	

	time_label = Label(section2,text="Timestamp:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	time_stamp = Label(section2, textvariable =timestamp, fg = "white", bg = "#5c5c5c")
	time_label.grid(row =1, column = 0,sticky = 'w')
	time_stamp.grid(row =1, column = 1,sticky = 'w')
	
	src_label = Label(section2,text="Source IP:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	src = Label(section2, textvariable =src_ip, fg = "white", bg = "#5c5c5c")
	src_label.grid(row =2, column = 0,sticky = ' w')
	src.grid(row =2, column = 1, sticky = 'w')
	
	dst_label = Label(section2,text="Destination IP:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	dst = Label(section2, textvariable =dst_ip, fg = "white", bg = "#5c5c5c")
	dst_label.grid(row =3, column = 0,sticky = ' w')
	dst.grid(row =3, column = 1, sticky = 'w')
	
	src_p_label = Label(section2,text="Source port:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	src_p = Label(section2, textvariable =src_port, fg = "white", bg = "#5c5c5c")
	src_p_label.grid(row =4, column = 0,sticky = ' w')
	src_p.grid(row =4, column = 1, sticky = 'w')
	
	dst_p_label = Label(section2,text="Destination port:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	dst_p = Label(section2, textvariable =dst_port, fg = "white", bg = "#5c5c5c")
	dst_p_label.grid(row =5, column = 0,sticky = ' w')
	dst_p.grid(row =5, column = 1, sticky = 'w')
	
	proto_label = Label(section2,text="Protocol:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	proto = Label(section2, textvariable =protocol, fg = "white", bg = "#5c5c5c")
	proto_label.grid(row =6, column = 0,sticky = ' w')
	proto.grid(row =6, column = 1, sticky = 'w')
	
	alert_label = Label(section2,text="Alert type:", fg = "white", bg = "#5c5c5c",padx = 20, pady = 10)
	alert = Label(section2, textvariable =alert_type, fg = "white", bg = "#5c5c5c")
	alert_label.grid(row =7, column = 0,sticky = ' w')
	alert.grid(row =7, column = 1, sticky = 'w')
	
	section3.grid_rowconfigure(0, weight = 0)
	section3.grid_rowconfigure(1, weight = 0)
	section3.grid_columnconfigure(0, weight = 1)
	section3.grid_columnconfigure(1, weight = 1)
	
	report = tk.StringVar(value=data['report'])
	subheading2 = Label(section3, text = "Incident Report", fg = 'white', bg = "#5c5c5c",font = ('Courier new', 12,'bold'), padx = 10, pady = 5)
	subheading2.grid(row = 0, column = 0)
	inc_report = Label(section3, textvariable = report, bg = 'white', wraplength = 400)
	inc_report.grid(row = 1 ,column = 0, columnspan = 2, padx = (20, 20), pady = (20,20))
	
	counter = tk.IntVar(value=data['counter'])
	
	section4.grid_columnconfigure(0, weight = 0,)
	section4.grid_columnconfigure(1, weight = 1)
	
	subheading3 = Label(section4, text = "Number of Alerts", fg = 'white', bg = "#5c5c5c",font = ('Courier new', 12,'bold'), padx = 10, pady = 5)
	counter_label = Label(section4, textvariable =counter, fg = "white", bg = "#5c5c5c")
	
	subheading3.grid(row = 0,padx = (20,20), pady = (20,20))
	counter_label.grid(row = 1,padx = (20,20), pady = (20,20))
	
	refresh()
	root.mainloop()

#This file starts the program
def main():
	global shared_data
	shared_data = {
		"timestamp":"No data",
		"src_ip":"No data",
		"dst_ip":"No data",
		"src_port":"No data",
		"dst_port":"No data",
		"protocol":"No data",
		"alert_type": "No data",
		"counter": 0,
		"report":"No data yet"
}
	
	ui(shared_data)
	

main()

