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

def create_memory_dump(process_name, dump_folder="C:\\MemoryDumps\\"):
    """
    Creates a memory dump of a running process and returns the dump file location.
    """
    # Ensure dump folder exists
    if not os.path.exists(dump_folder):
        os.makedirs(dump_folder)

    # Find process ID (PID)
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() == process_name.lower():
            pid = proc.info['pid']
            dump_file = os.path.join(dump_folder, f"{process_name}_{pid}.dmp")
            
            print(f"🔍 Found process {process_name} (PID: {pid}), dumping memory...")
            
            # Run Windows command to create dump
            dump_command = f"taskmgr /c /pid {pid} /m {dump_file}"
            subprocess.run(dump_command, shell=True, check=True)

            print(f"✅ Memory dump saved at: {dump_file}")
            return dump_file

    print(f"⚠️ Process {process_name} not found!")
    return None
def run_volatility(memory_dump):

    """
    Runs Volatility analysis on the given memory dump.
    """
    if not memory_dump:
        print("❌ No memory dump provided.")
        return

    print(f"🔍 Running Volatility on {memory_dump}...")

    # Run Volatility to extract process list & malware detection
    try:
        result_pslist = subprocess.run(["volatility", "-f", memory_dump, "--profile=Win10x64", "pslist"], capture_output=True, text=True)
        result_malfind = subprocess.run(["volatility", "-f", memory_dump, "--profile=Win10x64", "malfind"], capture_output=True, text=True)

        print("\n📝 Volatility Process List:\n", result_pslist.stdout)
        print("\n🚨 Potential Malware Injections:\n", result_malfind.stdout)
        
    except Exception as e:
        print(f"❌ Error running Volatility: {e}")

def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Executables", "*.exe")])
    file_label.configure(text=f"File: {file_path}")
    return file_path

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
        return "OTH"
    
    # Get the flags string and split it into individual flags
    flags_str = packet.tcp.flags_str  # e.g. "SYN, ACK" or "SYN" etc.
    flags = [f.strip().upper() for f in flags_str.split(',')]
    
    # Define mapping from common TCP flag names to short symbols
    mapping = {
         "SYN": "S",
         "ACK": "A",
         "PSH": "P",  # PSH often indicates data pushing; could be treated as data ('D') if preferred
         "FIN": "F",
         "RST": "R",
         "URG": "U"
    }
    
    # Define a preferred order of flags for our history string
    flag_order = ["SYN", "ACK", "PSH", "FIN", "RST", "URG"]
    history = ""
    for flag in flag_order:
        if flag in flags:
            history += mapping[flag]
    
    # Apply a simple heuristic to mimic training dataset keys:
    # If we get "SYN, ACK" -> "SA", convert to "ShAD" (since "ShAD" is common in your mapping)
    if history == "SA":
        return "ShAD"
    # Otherwise, if the history string is non-empty, return it; else default to "OTH"
    return history if history != "" else "OTH"



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

    # One-Hot Encoding for `proto` and `service`
    df["proto_udp"] = (df["proto"] == "UDP").astype(int) if "proto" in df.columns else 0
    df["service_dns"] = (df["service"] == "DNS").astype(int) if "service" in df.columns else 0
    df["service_http"] = (df["service"] == "HTTP").astype(int) if "service" in df.columns else 0
    df["service_irc"] = (df["service"] == "IRC").astype(int) if "service" in df.columns else 0

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
            service = packet.highest_layer if hasattr(packet, 'highest_layer') else "Unknown"

            # Set capture start time
            if start_time is None:
                start_time = packet.sniff_time

            # Calculate duration (in seconds)
            duration_sec = (packet.sniff_time - start_time).total_seconds()

            # Packet size
            orig_bytes = int(packet.length) if hasattr(packet, 'length') else 0
            resp_bytes = int(packet.captured_length) if hasattr(packet, 'captured_length') else 0

            # Connection state mapping (TCP-based only)
            conn_state = "OTH"  # Default
            if 'TCP' in proto:
                if hasattr(packet.tcp, 'flags'):
                    flags = packet.tcp.flags
                    if flags == "0x0002":
                        conn_state = "S0"  # SYN sent, no response
                    elif flags == "0x0004":
                        conn_state = "S1"  # SYN received
                    elif flags == "0x0008":
                        conn_state = "S3"  # SYN-ACK, connection established
                    elif flags == "0x0010":
                        conn_state = "SF"  # FIN flag, session closed
                    elif flags == "0x0020":
                        conn_state = "RSTR"  # RST sent
                    else:
                        conn_state = "OTH"  # Other cases

            # Additional metrics
            missed_bytes = int(packet.tcp.analysis_lost_segment) if hasattr(packet.tcp, 'analysis_lost_segment') else 0
            orig_pkts = 1  # Each packet is considered an individual entry
            orig_ip_bytes = orig_bytes
            resp_pkts = 1
            resp_ip_bytes = resp_bytes

            # Example frequency mapping loaded from training:
            history_freq_mapping = {'C': 14252, 'S': 5417, 'ShAdDaf': 1477, 'D': 978, 'Dd': 836, 
                                    'ShAdDaft': 102, 'ShAdfDr': 48, 'CCCC': 6, 'ShADadttcfF': 3, 
                                    'ShADadtcfF': 3, 'ShADadf': 2, 'CCC': 2, 'ShADacdtfF': 2, 
                                    'ShADadtctfF': 2, 'ShDadAf': 2, 'ShAdDatfr': 2, 'ShAfdtDr': 2, 
                                    'DdAtaFf': 1, 'ShADadtctfFR': 1, 'ShAdD': 1, 'ShADadttfF': 1, 
                                    'ShAdDatf': 1, 'ShAD': 1, 'ShAdDfr': 1, 'ShADad': 1, 'ShAdDa': 1}

            # After extracting history from a packet:
            history_str = extract_history(packet)
            # Map it to its frequency; default to 0 if not found:
            history = history_freq_mapping.get(history_str, 0)
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
    
    # subprocess.run(["cuckoo", "submit", file_path])
    # i=len(file_path)-1
    # while(file_path[i] != "/"):
    #     i-=1
    # file_name = file_path[i+1:]
    # create_memory_dump(file_name,dump_folder="/home/om/")

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
