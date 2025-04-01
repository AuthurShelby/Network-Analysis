from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template , jsonify 
from datetime import datetime , timezone
from collections import Counter
import mysql.connector
import time
import threading

app = Flask(__name__)
# mysql connection 
def get_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='12345678',
        database='network_analysis'
    )

# for anomaly logs
def create_anomaly_detection():
    conn = get_connection()
    cursor = conn.cursor()
    query = """
    CREATE TABLE IF NOT EXISTS anomaly_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        anomaly_type VARCHAR(50),
        source_ip VARCHAR(45),
        destination_ip VARCHAR(45) NULL,
        packet_rate FLOAT NULL,
        failed_attempts INT NULL,
        details TEXT
    )
    """
    cursor.execute(query)
    conn.commit()
    cursor.close()
    conn.close()


# intializing for anomalies detection 
packet_counts = Counter() # for DDos
failed_attempts = {} # for brute-force attack detection 
suspicious_ips = ["45.67.89.10"] # example of malicious ip
total_packets = 0
start_time = time.time() 

# for inserting the values inside the anomalies table
def insert_anomaly(anomaly_type, src_ip, dst_ip, packet_rate, failed_attempts, details):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
    INSERT INTO anomaly_logs (anomaly_type, source_ip, destination_ip, packet_rate, failed_attempts, details)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    cursor.execute(query , (anomaly_type , src_ip , dst_ip , packet_rate , failed_attempts, details))
    conn.commit()
    cursor.close()
    conn.close()

# network packets 
def packet_callback(packet):

    global packet_counts , failed_attempts , total_packets , start_time

    src_ip, src_port, dst_ip, dst_port, protocol = (None,) * 5
    protocol_type = 'Other' # if any other protocol appears
    payload, size = ('0 bytes',) * 2

    timestamp = datetime.fromtimestamp(packet.time , tz=timezone.utc ).strftime('%Y-%m-%d %H:%M:%S')
    
    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_type = 'TCP'
        
        elif UDP in packet:

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_type = 'UDP'
    
    # raw is the payload data or the actual data inside the packet
    
    if Raw in packet:
        RAWDATA = packet[Raw].load
        payload = f"{len(RAWDATA)} bytes"  
        
    size = len(packet) 
    
    # anomalies detection 
    # DDoS attack , Brute-Force , Malware
    if packet.haslayer(IP):
        if src_ip:
            packet_counts[src_ip]+=1
        duration = time.time() - start_time


        if duration > 0:
            rate = packet_counts[src_ip] / duration
            if rate > 100 : 
                insert_anomaly("DDoS Attack" , src_ip , None , rate , None  , f"High traffic detected: {rate:.2f} packets/sec")

    # Brute-force detection  SYN detection / if multiple SYN packets
    if packet.haslayer(TCP) and packet[TCP].flags == 2:
        failed_attempts[src_ip]= failed_attempts.get(src_ip , 0 )+1
        if failed_attempts[src_ip] > 10:
            insert_anomaly('Brute Force Attack' , src_ip , None , None , failed_attempts[src_ip] , "Multiple failed login attempts detected")
    
    #  Malware activity detection  --- of known suspecious ip
    if dst_ip in suspicious_ips:
        insert_anomaly("Malware Activity" , src_ip , dst_ip , None , None , f"Suspicious connection detected to {dst_ip}")

    # Reseting the time for reducing the incorrect rate
    if start_time > 60:
        start_time = time.time()
        for ip in list(packet_counts.keys()):
            packet_counts[ip] = max(0 , packet_counts[ip] - 50) # Reduce by 50 instead of fully resting the packet_count

    # if any database error occurs
    # while storing the data 
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = """
            INSERT INTO packets(timestamp, src_ip, src_port, dst_ip, dst_port, protocol, protocol_type, payload, size)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, protocol_type, payload, size))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Database Error: {e}")


def start_sniffing():
    sniff(prn=packet_callback, filter='ip', store=0)

# for fetching the packets 
# and returning the packets to the html page 
#  /get_packets is the end point  
@app.route('/get_packets')
def get_packets():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM packets ORDER BY id DESC')
    packets = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(packets)

# /get_anomalies for fetching 
# All the DDoS attack , Brute-Force , Malware
@app.route('/get_anomalies')
def get_anomalies():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM anomaly_logs ORDER BY id DESC')
    anomalies = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(anomalies)

@app.route('/')
def index():
    # rendering the network page
    return render_template('index.html')

if __name__ == '__main__':
    # threading is used so that multiple process can happen internally 
    create_anomaly_detection() # creating anomaly table 
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(debug=True)
