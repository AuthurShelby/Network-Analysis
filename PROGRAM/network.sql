
USE network_analysis ; 
DESC packets ; 

SELECT COUNT(*) AS packetcount FROM packets ;
SELECT * FROM packets ; 
TRUNCATE TABLE packets ; 

ALTER TABLE packets MODIFY COLUMN `timestamp` DATETIME; 

SELECT payload , protocol FROM packets WHERE protocol_type = 'UDP'; 

SELECT * FROM packets WHERE id = (select id from packets order by  id desc limit 1); 

ALTER TABLE packets ADD `size` INT NOT NULL ;  

-- index for timestamp
CREATE INDEX idx_timestamp ON packets(timestamp);

-- index for source ip 

CREATE INDEX idx_src_ip ON packets(src_ip);

-- index for destination ip 

CREATE INDEX idx_dst_ip ON packets(dst_ip);

-- index for protocol id

CREATE INDEX idx_protocol ON packets(protocol) ;

-- if we are searching based on source ip , dest ip , protocol 

CREATE INDEX idx_src_dst_proto ON network_logs (src_ip, dst_ip, protocol);


-- ANOMALY DETECTION TABLE 
 CREATE TABLE anomaly_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        anomaly_type VARCHAR(50),
        source_ip VARCHAR(45),
        destination_ip VARCHAR(45) NULL,
        packet_rate FLOAT NULL,
        failed_attempts INT NULL,
        details TEXT
);
DROP TABLE anomaly_logs ; 

SELECT * FROM anomaly_logs ; 

SELECT anomaly_type , COUNT(*) FROM anomaly_logs GROUP BY anomaly_type; 

CREATE TABLE bottleneck_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        bottleneck_type VARCHAR(50),
        source_ip VARCHAR(45) NULL,
        packet_loss_rate FLOAT NULL,
        average_latency FLOAT NULL,
        data_transferred FLOAT NULL,
        details TEXT
);
DESC anomaly_logs ; 
SELECT * FROM packets ; 
SELECT * FROM bottleneck_logs ; 
SELECT * FROM anomaly_logs ; 

TRUNCATE TABLE packets ; 
TRUNCATE TABLE bottleneck_logs ; 
TRUNCATE TABLE anomaly_logs ; 
