from scapy.all import sniff, IP, TCP, UDP, Raw , ICMP , ARP , DNS , SSL , TLS
from flask import Flask, render_template , jsonify , redirect
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
def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    # creating the packets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(50) NOT NULL,
    src_port VARCHAR(10),
    dst_ip VARCHAR(50) NOT NULL,
    dst_port VARCHAR(10),
    protocol VARCHAR(10) NOT NULL,
    protocol_type VARCHAR(10),
    payload TEXT,
    size INT NOT NULL,
    INDEX (timestamp),
    INDEX (src_ip),
    INDEX (dst_ip),
    INDEX (protocol))""")
    # creating the anomaly_logs table 
    cursor.execute( """
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
    """)
    # creating the bottleneck_logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bottleneck_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        bottleneck_type VARCHAR(50),
        source_ip VARCHAR(45) NULL,
        packet_loss_rate FLOAT NULL,
        average_latency FLOAT NULL,
        data_transferred FLOAT NULL,
        details TEXT
    )""")
    conn.commit()
    cursor.close()
    conn.close()




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

# for inserting the values inside the bottlenecks table
def insert_bottlenecks(bottleneck_type , src_ip , packet_loss_rate , avg_latency , data_transferred , details):
    conn = get_connection()
    cursor = conn.cursor()
    query="""
    INSERT INTO bottleneck_logs(bottleneck_type , source_ip , packet_loss_rate , average_latency , data_transferred , details) 
    VALUES(%s , %s , %s , %s , %s , %s)
    """
    cursor.execute(query , (bottleneck_type , src_ip , packet_loss_rate , avg_latency , data_transferred , details))
    conn.commit()
    cursor.close()
    conn.close()

# the set of global variables that are used for
# detecting the anomalies and bottlenecks
# intializing for anomalies detection 
packet_counts = Counter() # for DDos
failed_attempts = {} # for brute-force attack detection 
suspicious_ips = ["45.67.89.10"] # example of malicious ip
start_time = time.time() 

# intializing for bottlenecks detection
# packet loss detection
total_packets = 0
packet_loss_count = 0
# Track latency samples 
latency_samples= []
# Track bandwidth usage
bandwidth_usage = Counter()
start_bandwidth_time = time.time()

# Track connection timeouts
connection_attempts = Counter()
timeout_threshold = 5  # Max failed attempts before logging timeout

# network packets 
def packet_callback(packet):
    global packet_counts , failed_attempts , total_packets , start_time , packet_loss_count , latency_samples , bandwidth_usage, start_bandwidth_time

    src_ip, src_port, dst_ip, dst_port, protocol = (None,) * 5
    protocol_type = 'Other' # if any other protocol appears
    payload, size = ('0 bytes',) * 2

    timestamp = datetime.fromtimestamp(packet.time , tz=timezone.utc ).strftime('%Y-%m-%d %H:%M:%S')
    
    # catching the protocols
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Check known protocol types
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_type = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_type = 'UDP'
        elif ICMP in packet:
            protocol_type = 'ICMP'
        elif packet.haslayer(ARP):
            protocol_type = 'ARP'
        elif packet.haslayer(DNS):
            protocol_type = 'DNS'
        elif packet.haslayer(SSL) or packet.haslayer(TLS):
            protocol_type = 'SSL/TLS'
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


    # Bottle-necks detection
    # packets count part
    total_packets+=1
    if not packet.haslayer(IP):
        packet_loss_count+=1
    
    # packet loss_rate
    if total_packets % 10 == 0:
        loss_rate = (packet_loss_count/total_packets)*100
        if loss_rate > 5:
            insert_bottlenecks("Packet loss" , None , loss_rate , None , None , f"Packet loss rate: {loss_rate:.2f}%")
    
    # finding latency 
    # if it get's the acknowledgement aka 'ack'
    if TCP in packet and hasattr(packet[TCP] , 'ack'): 
        current_time = time.time()
        latency_samples.append(current_time - packet.time)

    if len(latency_samples) > 10:
        avg_latency = (sum(latency_samples) / len(latency_samples) ) * 1000
        # if the average latency is greater than 200ms
        # then it is considered as a bottleneck
        if avg_latency > 200: 
            insert_bottlenecks("High latency" , None , None , avg_latency , None , f"High latency detected: {avg_latency:.2f} ms")
        latency_samples = []

    # Bandwidth usage detection
    if IP in packet:
        src_ip = packet[IP].src
        packet_size = len(packet)
        bandwidth_usage[src_ip] += packet_size
        # Check if bandwidth usage exceeds threshold
        if time.time() - start_bandwidth_time > 60:
            for ip, data_used in bandwidth_usage.items():
                if data_used > 10 * 1024 * 1024:  # 10MB threshold
                        insert_bottlenecks("High Bandwidth Usage", ip, None, None, data_used / (1024 * 1024), 
                                      f"Excessive data transfer detected: {data_used / (1024 * 1024):.2f} MB in 60 sec")
            bandwidth_usage.clear()
            start_bandwidth_time = time.time()

    # Connection timeout detection
    if TCP in packet and packet[TCP].flags == 2:  # SYN flag set (connection attempt)
        connection_attempts[src_ip] += 1
    elif TCP in packet and packet[TCP].flags in [16, 18]:  # ACK or SYN-ACK flag
        connection_attempts[src_ip] = 0  # Reset on successful handshake

    if connection_attempts[src_ip] > timeout_threshold:
        insert_bottlenecks("Connection Timeout", src_ip, None, None, None, 
                          "Multiple connection attempts failed")
        connection_attempts[src_ip] = 0  # Reset after logging

    # Reseting the time for reducing the incorrect rate
    if time.time() - start_time > 60:
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
    sniff(iface = 'Wi-Fi',prn=packet_callback, filter='ip', store=0)



# for fetching the packets 
# and returning the packets to the html page 
#  /get_packets is the end point  
@app.route('/get_packets')
def get_packets():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM packets ORDER BY id DESC LIMIT 50')
    packets = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(packets)

@app.route('/get_protocol_distribution')
def get_protocol_distribution():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Query to count the number of packets for each protocol
    cursor.execute('SELECT protocol_type, COUNT(*) as count FROM packets GROUP BY protocol_type')
    protocol_data = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    # Return the data as JSON
    return jsonify(protocol_data)

# /get_anomalies for fetching 
# All the DDoS attack , Brute-Force , Malware
@app.route('/get_anomalies')
def get_anomalies():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM anomaly_logs ORDER BY id DESC LIMIT 50')
    anomalies = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(anomalies)

# /get_bottlenecks for fetching
# All the bottlenecks that are detected
# such as packet loss , high latency
@app.route('/get_bottlenecks')
def get_bottlenecks():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM bottleneck_logs ORDER BY id DESC LIMIT 50')
    bottlenecks = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(bottlenecks)

@app.route('/get_graph_data')
def get_graph_data():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch anomalies
    cursor.execute('SELECT timestamp, packet_rate FROM anomaly_logs ORDER BY id DESC LIMIT 50')
    anomalies = cursor.fetchall()

    # Fetch bottlenecks
    cursor.execute('SELECT timestamp, average_latency FROM bottleneck_logs ORDER BY id DESC LIMIT 50')
    bottlenecks = cursor.fetchall()

    cursor.close()
    conn.close()

    # Convert timestamps to readable format
    anomaly_data = [{"timestamp": a["timestamp"].strftime('%Y-%m-%d %H:%M:%S'), "packet_rate": a["packet_rate"] or 0} for a in anomalies]
    bottleneck_data = [{"timestamp": b["timestamp"].strftime('%Y-%m-%d %H:%M:%S'), "average_latency": b["average_latency"] or 0} for b in bottlenecks]

    return jsonify({"anomalies": anomaly_data, "bottlenecks": bottleneck_data})


# root '/' is the main page
@app.route('/')
def root():
    return redirect('/packets')  # Redirect to the packets page

@app.route('/packets')
def index():
    # rendering the network page
    return render_template('packets.html')

@app.route('/anomalies_bottlenecks')
def anomalies_bottlenecks():
    # rendering the anomalies and bottlenecks page
    return render_template('anomalies_bottlenecks.html')

@app.route('/graph')
def graph():
    # rendering the graph page
    return render_template('graph.html')

if __name__ == '__main__':
    # threading is used so that multiple process can happen internally 
    create_tables() # creating anomaly , bottlenecks table 
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(debug=True)