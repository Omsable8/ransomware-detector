import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import subprocess
import pandas as pd
import joblib
import pyshark
import psutil
import time
import os
# Load Pre-Trained Model
model = joblib.load("models/XGBoost_network.pkl")

# GUI Setup
app = ctk.CTk()
app.geometry("600x400")
app.title("Ransomware Detector")
app.resizable(False,False)

csv_path="network_features.csv"



def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Executables", "*.exe")])
    file_label.configure(text=f"File: {file_path}")
    return file_path


def get_service_by_port(packet):
    """
    Determines the network service based on the transport layer and destination/source port.
    Checks for:
      - HTTP: TCP port 80
      - HTTPS: TCP port 443
      - IRC: TCP port 6667
      - DNS: UDP port 53 (or TCP port 53 if applicable)
      - NTP: UDP port 123
    Returns the service as an uppercase string, or "UNKNOWN" if not identified.
    """
    try:
        # Check if the packet has TCP layer
        if hasattr(packet, 'tcp'):
            dst_port = int(packet.tcp.dstport)
            src_port = int(packet.tcp.srcport)
            if dst_port == 80 or src_port == 80:
                return "http"
            elif dst_port == 443 or src_port == 443:
                return "https"
            elif dst_port == 6667 or src_port == 6667:
                return "irc"
            elif dst_port == 53 or src_port == 53:
                return "dns"
            elif dst_port == 123 or src_port == 123:
                return "ntp"
            elif dst_port == 22 or src_port == 22:
                return "ssh"
            
        # Check if the packet has UDP layer
        if hasattr(packet, 'udp'):
            dst_port = int(packet.udp.dstport)
            src_port = int(packet.udp.srcport)
            if dst_port == 53 or src_port==53:
                return "dns"
            elif dst_port == 123 or src_port == 123:
                return "ntp"
            elif dst_port == 22 or src_port == 22:
                return "ssh"
        return "UNKNOWN"
    except Exception as e:
        # In case of any error, return UNKNOWN
        print("ERROR GETTING SERVICE: ",e)
        return "UNKNOWN"


def extract_conn(packet):
    # Connection state mapping (TCP-based only)
    proto = packet.transport_layer if hasattr(packet, 'transport_layer') else "Unknown"

    conn_state = "OTH"  # Default
    if 'TCP' in proto:
        if hasattr(packet.tcp, 'flags'):
            flags = packet.tcp.flags
            if flags == "0x0002":
                conn_state = "S0"  # SYN sent, no response
            elif flags == "0x0010":
                conn_state = "S1"  # connection established not terminated
            elif flags == "0x0012":
                conn_state = "S3"  # SYN-ACK, connection established and close attempt by resp
            elif flags == "0x0001":
                conn_state = "SF"  # FIN flag, session closed normally (bytes in summary)
            elif flags == "0x0004":
                conn_state = "RSTR"  # RST sent by responder
            else:
                conn_state = "OTH"  # Other cases
    elif 'UDP' in proto:
        conn_state = "SF"
    return conn_state

# Extract TCP history feature (same as your one-packet capture function)
def extract_history(packet):
    """
    Extracts a history string from a TCP packet using its flags.
    This function uses a heuristic:
      - It splits the tcp.flags_str field,
      - Maps common flags (SYN, ACK, PSH, FIN, RST, URG) to single letters,
      - And then creates a string in a defined order.
    If the packet is not TCP or no flags are present, returns "OTH".
    """
    # Ensure packet has a TCP layer
    if not hasattr(packet, 'tcp') or not hasattr(packet.tcp, 'flags_str'):
        return 836 # FOR Dd = 836

    # Get the flags string and split it into individual flags
    flags_str = packet.tcp.flags_str  # e.g. "S","A" etc.

    print("FLAGS STRING::",flags_str)
    
    # Define mapping from common TCP flag names to short symbols
    # mapping = {
    #      "SYN": "S",
    #      "ACK": "A",
    #      "PSH": "P",  # PSH often indicates data pushing; could be treated as data ('D') if preferred
    #      "FIN": "F",
    #      "RST": "R",
    #      "DATA": "D"
    # }
    
    # Define a preferred order of flags for our history string
    flag_order = ["S", "A", "P", "F", "R", "D"]
    
    history = ""
    for flag in flags_str:
        if flag in flag_order:
            history += flag
    
    # Apply a simple heuristic to mimic training dataset keys:
    # If we get "SYN, ACK" -> "SA", convert to "ShAD" (since "ShAD" is common in your mapping)
    if history == "SA":
        return "Sh"
    elif history == "SAD":
        return "ShAD"
    # Otherwise, if the history string is non-empty, return it; else default to "OTH"
    history = history if history != "" else "OTH"

    print("HISTORY STRING : ", history)
    
    return history



def clean_network(file_path="network_features.csv"):
    """
    Reads network features CSV and preprocesses it to match the trained ML model's feature set.

    Parameters:
        file_path (str): Path to the network features CSV.

    Returns:
        pd.DataFrame: Processed dataframe with required features.
    """
    # Load dataset
    df = pd.read_csv(file_path)

    # Ensure expected columns exist, fill missing if needed
    required_cols = [
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "duration",
        "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "history",
        "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"
    ]
    df = df[required_cols] if all(col in df.columns for col in required_cols) else df.fillna(0)

    conn_state_mp = {"S0":2,"S1":3,"S3":4,"SF":5,"RSTR":1,"OTH":0}
    df["conn_state"] = df["conn_state"].map(conn_state_mp)

    # Example frequency mapping loaded from training:
    history_freq_mapping = {'C': 14252, 'S': 5417, 'ShAdDaf': 1477, 'D': 978, 'Dd': 836, 
                            'ShAdDaft': 102, 'ShAdfDr': 48, 'CCCC': 6, 'ShADadttcfF': 3, 
                            'ShADadtcfF': 3, 'ShADadf': 2, 'CCC': 2, 'ShADacdtfF': 2, 
                            'ShADadtctfF': 2, 'ShDadAf': 2, 'ShAdDatfr': 2, 'ShAfdtDr': 2, 
                            'DdAtaFf': 1, 'ShADadtctfFR': 1, 'ShAdD': 1, 'ShADadttfF': 1, 
                            'ShAdDatf': 1, 'ShAD': 1, 'ShAdDfr': 1, 'ShADad': 1, 'ShAdDa': 1, "OTH":0}



    # Map it to its frequency; default to 0 if not found:
    hist = []
    for h in df["history"]:
        hist.append(history_freq_mapping.get(h,0))
    df["history"] = hist
    
    # One-Hot Encoding for `proto` and `service`
    df["proto_udp"] = (df["proto"] == "UDP").astype(int) if "proto" in df.columns else 0
    df["service_dns"] = (df["service"] == "dns").astype(int) if "service" in df.columns else 0
    df["service_http"] = (df["service"] == "http").astype(int) if "service" in df.columns else 0
    df["service_https"] = (df["service"] == "https").astype(int) if "service" in df.columns else 0
    df["service_irc"] = (df["service"] == "irc").astype(int) if "service" in df.columns else 0
    df["service_ntp"] = (df["service"] == "ntp").astype(int) if "service" in df.columns else 0
    df["service_ssh"] = (df["service"] == "ssh").astype(int) if "service" in df.columns else 0

    # Drop non-numeric categorical columns
    df.drop(columns=["proto", "service","id.orig_h","id.resp_h"], errors="ignore", inplace=True)
    df.to_csv(file_path,index=False)
    return df




def capture_network_traffic(interface="Ethernet", output_csv="network_features.csv"):
    """
    Captures live network traffic and extracts features.
    
    Parameters:
        interface (str): The network interface to capture from (Check `tshark -D` for options).
        output_csv (str): File to save extracted network features.
    """
    print(f"📡 Capturing network traffic on {interface}")

    # Capture packets
    cap = pyshark.LiveCapture(interface=interface)

    extracted_data = []
    
    # Capture start time
    start_time = None

    for packet in cap.sniff_continuously(packet_count=1):
        try:
            # Extract basic connection info
            id_orig_h = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
            id_resp_h = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
            id_orig_p = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "Unknown"
            id_resp_p = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "Unknown"
            proto = packet.transport_layer if hasattr(packet, 'transport_layer') else "Unknown"
            service = get_service_by_port(packet)


            # Calculate duration (in seconds)
            duration_sec = float(packet.frame_info.time_delta) if hasattr(packet, "frame_info") else 0

            # Packet size
            orig_bytes = int(packet.length) if hasattr(packet, 'length') else 0
            resp_bytes = int(packet.captured_length) if hasattr(packet, 'captured_length') else 0

            # Connection state mapping (TCP-based only)
            conn_state = extract_conn(packet)

            # Additional metrics
            missed_bytes = int(packet.tcp.analysis_lost_segment) if hasattr(packet.tcp, 'analysis_lost_segment') else 0
            orig_pkts = 1  # Each packet is considered an individual entry
            orig_ip_bytes = orig_bytes
            resp_pkts = 1
            resp_ip_bytes = resp_bytes

            history = extract_history(packet)
            # Store extracted data
            extracted_data.append([
                id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration_sec, orig_bytes, resp_bytes,
                conn_state, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes
            ])

            break
        except Exception as e:
            print(f"⚠️ Error processing packet: {e}")

    # Convert to DataFrame
    columns = [
        "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes",
        "resp_bytes", "conn_state", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"
    ]
    df = pd.DataFrame(extracted_data, columns=columns)

    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"✅ Network traffic features saved to {output_csv}")



def analyze_file():
    file_path = file_label.cget("text").replace("File: ", "")
    if not file_path:
        messagebox.showerror("Error", "Please select a file first!")
        return

    status_label.configure(text="🔍 Running File...")
    subprocess.run("start "+file_path,shell=True)

    status_label.configure(text="🛡 Extracting Features...")
    

    status_label.configure(text="📡 Capturing Network Traffic...")

    capture_network_traffic()

    clean_network()

    status_label.configure(text="📊 Cleaning Data & Running Model...")

    df = pd.read_csv(csv_path)

    y_pred = model.predict(df)
    
    result = "Malware Detected 🚨" if y_pred[0] == 1 else "Benign ✅"
    print(result)
    result_label.configure(text=result, fg_color="red" if y_pred[0] == 1 else "green")

# GUI Elements
title_label = ctk.CTkLabel(app, text="Ransomware Detector", font=("Arial", 24))
title_label.pack(pady=10)

upload_btn = ctk.CTkButton(app, text="Upload File", command=upload_file)
upload_btn.pack(pady=5)

file_label = ctk.CTkLabel(app, text="No file selected", font=("Arial", 12))
file_label.pack()

analyze_btn = ctk.CTkButton(app, text="Analyze", fg_color="red", command=analyze_file)
analyze_btn.pack(pady=10)

status_label = ctk.CTkLabel(app, text="Status: Waiting...", font=("Arial", 12))
status_label.pack()

result_label = ctk.CTkLabel(app, text="", font=("Arial", 16))
result_label.pack(pady=10)

app.mainloop()
