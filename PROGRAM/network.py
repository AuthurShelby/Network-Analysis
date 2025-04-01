from scapy.all import sniff, IP, TCP, UDP, Raw
from flask import Flask, render_template 
from datetime import datetime
import mysql.connector
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

# network packets 
def packet_callback(packet):

    src_ip, src_port, dst_ip, dst_port, protocol = (None,) * 5
    protocol_type = 'Other' # if any other protocol appears
    payload, size = ('0 bytes',) * 2

    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    
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
    return ''.join(f"""
    <tr>
        <td>{packet['timestamp']}</td>
        <td>{packet['src_ip']}</td>
        <td>{packet['src_port']}</td>
        <td>{packet['dst_ip']}</td>
        <td>{packet['dst_port']}</td>
        <td>{packet['protocol_type']}</td>
        <td>{packet['payload']}</td>
        <td>{packet['size']} bytes</td>
    </tr>
    """ for packet in packets)

@app.route('/')
def index():
    # rendering the network page
    return render_template('index.html')

if __name__ == '__main__':
    # threading is used so that multiple process can happen internally 
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(debug=True)
