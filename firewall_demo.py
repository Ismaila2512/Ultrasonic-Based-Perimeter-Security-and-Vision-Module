import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import docker # type: ignore
import matplotlib.pyplot as plt
import seaborn as sns
import subprocess
from scapy.all import IP, TCP, UDP, Ether, send  # type: ignore # For packet simulation (non-live)


# Step 1: Generate synthetic network traffic data (1000 packets)
np.random.seed(42)  # For reproducibility
n_samples = 1000
data = {
    
    'src_ip': np.random.choice(['192.168.1.' + str(i) for i in range(1, 255)], n_samples),
    'dst_port': np.random.randint(20, 65535, n_samples),
    'packet_size': np.random.normal(500, 200, n_samples),  # Mean 500 bytes
    'protocol': np.random.choice(['TCP', 'UDP'], n_samples),
    'label': np.random.choice([0, 1], n_samples, p=[0.9, 0.1])  # 90% safe, 10% attacks
   }

df = pd.DataFrame(data)
print(f"Generated {len(df)} synthetic packets.")

# Step 2: Basic Layer - Rule-based blocking (e.g., block known bad IPs)
known_bad_ips = ['192.168.1.100', '192.168.1.200']  # Simulated threat list
df['blocked_basic'] = df['src_ip'].isin(known_bad_ips)
blocked_basic = df[df['blocked_basic']]
df = df[~df['blocked_basic']]  # Remove blocked
print(f"Basic layer blocked {len(blocked_basic)} known threats.")

# Step 3: AI/ML Model - Anomaly detection on remaining traffic
features = ['dst_port', 'packet_size']
X = df[features].copy()
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest (learns "normal" traffic)
model = IsolationForest(contamination=0.1, random_state=42)  # 10% expected anomalies
df['anomaly'] = model.fit_predict(X_scaled)  # -1 = anomaly (virus), 1 = normal
suspicious = df[df['anomaly'] == -1]
df = df[df['anomaly'] == 1]  # "Allow" normals
print(f"AI/ML detected {len(suspicious)} suspicious activities.")

# Step 4: Memory System - Save model and threats
os.makedirs('memory', exist_ok=True)
joblib.dump(model, 'memory/threat_model.pkl')
joblib.dump(known_bad_ips, 'memory/blocked_ips.pkl')
threats_df = pd.concat([blocked_basic, suspicious])  # All threats
threats_df.to_csv('memory/threats_log.csv', index=False)
print("Threats saved to memory.")

# Step 5: Sandbox Quarantine - Simulate analysis in Docker container
client = docker.from_env()
suspicious_ips = suspicious['src_ip'].unique()[:1]  # Quarantine first suspicious IP (demo limit)
for ip in suspicious_ips:
    try:
        # Create a simple container to "analyze" (echo the IP as quarantined)
        container = client.containers.run(
            "alpine:latest",  # Lightweight image
            command=["sh", "-c", f"echo 'Analyzing quarantined IP: {ip}' && sleep 2"],
            detach=True, auto_remove=True
            )
        
        logs = container.logs().decode('utf-8')
        print(f"Sandbox analysis for {ip}: {logs.strip()}")
        container.wait()
    except Exception as e:
        print(f"Sandbox error for {ip}: {e} (Ensure Docker is running)")
        
        # Step 6: Visualization - Plot safe vs. attacks
        plt.figure(figsize=(10, 6))
        # Safe traffic (healthy cells)
        safe = df.sample(min(200, len(df)))  # Subsample for clarity
        plt.scatter(safe['dst_port'], safe['packet_size'], c='green', label='Healthy Cells (Safe)', alpha=0.6, s=20)
        # Attacks (viruses)
        attacks = threats_df.sample(min(50, len(threats_df)))
        plt.scatter(attacks['dst_port'], attacks['packet_size'], c='red', label='Viruses (Attacks)', alpha=0.8, s=50)
        plt.xlabel('Destination Port')
        plt.ylabel('Packet Size (bytes)')
        plt.title('Bio-Inspired Firewall Demo: Traffic Visualization')
        plt.legend()
        plt.savefig('visualization.png')  # Save image
        plt.show()  # Display in VS Code (if matplotlib backend supports)
        # Bonus: Simulate sending a safe packet with Scapy (non-live, just print)
        safe_packet = Ether() / IP(src='192.168.1.1', dst='192.168.1.2') / TCP(dport=80)
        print(f"Simulated safe packet: {safe_packet.summary()}")

        print("Demo complete! Check 'visualization.png' and 'memory/' folder.")
   