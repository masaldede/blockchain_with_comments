# ⛓️ Simple Blockchain Network Simulator (with Proof of Work)

## 🚀 Purpose  
This project simulates a basic blockchain system across multiple distributed nodes using HTTP communication. It demonstrates fundamental blockchain mechanics such as:

- Proof-of-Work (PoW) mining  
- Hash chaining  
- Ledger synchronization between nodes  
- Server communication over REST endpoints

## 📋 Features  
- Mines blocks using SHA-256 hashing  
- Communicates between three nodes (`node-a`, `node-b`, and `node-c`)  
- Proof-of-work configurable via `proof_number` and `proof_value`  
- Uses a simple `0000` prefix as a valid proof target  
- Fully commented to support educational understanding

## 🧠 Concepts Covered  
- Hashing with `hashlib.sha256`  
- Proof of Work mechanics  
- Building and validating chains  
- Simulating nodes via HTTP requests  
- JSON handling for block data

## 🛠️ Technologies Used  
- Python 3.x  
- `hashlib`, `time`, `urllib.request`, `json`  
- Simulated HTTP servers (e.g., Flask, PHP backends)

## 🌐 Node Setup  
The project uses three sample nodes:
```python
server_a = "http://node-a.example.com"
server_b = "http://node-b.example.com"
server_c = "http://node-c.example.com"

🔧 How It Works
	1.	A node retrieves the last block hash from another node
	2.	It finds a valid proof-of-work solution
	3.	It sends the new block to other ledgers via HTTP POST
	4.	Chains remain synced as long as hashes and proof values match

🧪 How to Run
	1.	Update server URLs to your local/test endpoints
	2.	Run the script in Python 3:

python Blockchain_WithComments.py

🧠 Learning Outcomes
	•	Understand block structure and how proof-of-work works
	•	Learn inter-node communication in a blockchain
	•	Apply basic cryptography in practice
	•	Simulate lightweight distributed ledger interaction

📌 Next Steps
	•	Replace PHP endpoints with a Python backend (Flask API)
	•	Add consensus mechanism and fork resolution
	•	Implement transaction handling and wallets
	•	Visualize blockchain with a web dashboard
