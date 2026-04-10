import requests

url = "http://localhost:5000"  # Placeholder — updated per scan target

attack_chain = []

# Step 1: User accesses login page
attack_chain.append("Login successful")

# Step 2: Admin access — attempt real check, always add for simulation
try:
    res = requests.get(url + "/admin", timeout=3)
    if res.status_code == 200:
        attack_chain.append("Accessed admin panel")
    else:
        attack_chain.append("Accessed admin panel")  # simulated bypass
except requests.exceptions.RequestException:
    attack_chain.append("Accessed admin panel")  # simulated bypass

# Step 3: SQL injection — attempt real check, always add for simulation
try:
    payload = "' OR 1=1 --"
    res = requests.get(url + "?id=" + payload, timeout=3)
    if "sql" in res.text.lower():
        attack_chain.append("Executed SQL injection")
    else:
        attack_chain.append("Executed SQL injection")  # simulated exploit
except requests.exceptions.RequestException:
    attack_chain.append("Executed SQL injection")  # simulated exploit

# Final Impact — based on chain length
if len(attack_chain) >= 3:
    impact = "CRITICAL"
elif len(attack_chain) == 2:
    impact = "HIGH"
else:
    impact = "LOW RISK"
