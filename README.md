# wifi-
wifi переключатель, написанный на python , вкл откл интернета только нужно указать вашу сеть. Есть функции ping, terminal. В 
ADAPTER_NAME = "Беспроводная сеть 2" заменить на название своей сети[wifi переключатель.py](https://github.com/user-attachments/files/22459610/wifi.py)


---------------------------------------------------------------------------------------------------------------------------
import os
import tkinter as tk
import subprocess
import psutil

ADAPTER_NAME = "Беспроводная сеть 2"

root = tk.Tk()
root.title("Network Control Panel")
root.geometry("1000x500")
root.resizable(False, False)

# ====== STATUS ======
status_label = tk.Label(root, text="Status: Unknown", font=("Arial", 14), width=10)
status_label.pack(pady=5)

# ====== TRAFFIC ======
traffic_label = tk.Label(root, text="Sent: 0 MB | Received: 0 MB", font=("Arial", 12))
traffic_label.pack(pady=5)

# ====== INFO FIELDS ======
info_frame = tk.Frame(root)
info_frame.pack(pady=5)

tk.Label(info_frame, text="IP:").grid(row=0, column=0, sticky="e")
ip_entry = tk.Entry(info_frame, width=20)
ip_entry.grid(row=0, column=1)

tk.Label(info_frame, text="DNS:").grid(row=1, column=0, sticky="e")
dns_entry = tk.Entry(info_frame, width=20)
dns_entry.grid(row=1, column=1)

tk.Label(info_frame, text="Gateway:").grid(row=2, column=0, sticky="e")
gw_entry = tk.Entry(info_frame, width=20)
gw_entry.grid(row=2, column=1)

tk.Label(info_frame, text="Port:").grid(row=3, column=0, sticky="e")
port_entry = tk.Entry(info_frame, width=20)
port_entry.grid(row=3, column=1)

# ====== TERMINAL OUTPUT ======
terminal = tk.Text(root, height=1, bg="black", fg="lime", insertbackground="white")
terminal.pack(fill="both", expand=True, padx=1, pady=(5,0))

def write_terminal(text):
    terminal.insert(tk.END, text + "\n")
    terminal.see(tk.END)

# ====== FUNCTIONS ======
def update_network_info():
    try:
        ip_cmd = f'powershell -Command "(Get-NetIPAddress -InterfaceAlias \'{ADAPTER_NAME}\' -AddressFamily IPv4).IPAddress"'
        dns_cmd = f'powershell -Command "(Get-DnsClientServerAddress -InterfaceAlias \'{ADAPTER_NAME}\' -AddressFamily IPv4).ServerAddresses"'
        gw_cmd = f'powershell -Command "(Get-NetIPConfiguration -InterfaceAlias \'{ADAPTER_NAME}\').IPv4DefaultGateway.NextHop"'
        ip = subprocess.check_output(ip_cmd, shell=True).decode().strip()
        dns = subprocess.check_output(dns_cmd, shell=True).decode().strip()
        gw = subprocess.check_output(gw_cmd, shell=True).decode().strip()
        ip_entry.delete(0, tk.END); ip_entry.insert(0, ip)
        dns_entry.delete(0, tk.END); dns_entry.insert(0, dns)
        gw_entry.delete(0, tk.END); gw_entry.insert(0, gw)
    except:
        pass

def internet_status():
    cmd = f'powershell -Command "Get-NetAdapter -Name \'{ADAPTER_NAME}\' | Select-Object -ExpandProperty Status"'
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return "Up" in result.stdout

def update_indicator():
    if internet_status():
        status_label.config(bg="green", text="Status: Internet ON")
    else:
        status_label.config(bg="red", text="Status: Internet OFF")
    update_network_info()

def internet_on():
    os.system(f'powershell -Command "Enable-NetAdapter -Name \'{ADAPTER_NAME}\' -Confirm:$false"')
    update_indicator()
    write_terminal("[INFO] Internet enabled")

def internet_off():
    os.system(f'powershell -Command "Disable-NetAdapter -Name \'{ADAPTER_NAME}\' -Confirm:$false"')
    update_indicator()
    write_terminal("[INFO] Internet disabled")

def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        output = e.output.decode(errors="ignore") if e.output else str(e)
    write_terminal(output)

# ====== COMMAND BUTTONS ======
button_frame = tk.Frame(root)
button_frame.place(x=5, y=5)

def add_button(text, cmd):
    return tk.Button(button_frame, text=text, width=12, command=cmd, font=("Arial", 10))

add_button("ON", internet_on).pack(pady=2)
add_button("OFF", internet_off).pack(pady=2)
add_button("PING", lambda: run_command("ping 8.8.8.8 -n 4")).pack(pady=2)
add_button("TRACEROUTE", lambda: run_command("tracert 8.8.8.8")).pack(pady=2)
add_button("ARP", lambda: run_command("arp -a")).pack(pady=2)
add_button("NETSTAT", lambda: run_command("netstat -ano")).pack(pady=2)
add_button("IPCONFIG", lambda: run_command("ipconfig /all")).pack(pady=2)

# ====== TERMINAL INPUT ======
input_frame = tk.Frame(root)
input_frame.pack(fill="x", padx=10, pady=5)

command_entry = tk.Entry(input_frame, bg="black", fg="lime", insertbackground="white")
command_entry.pack(side="left", fill="x", expand=True)

def run_from_entry(event=None):
    cmd = command_entry.get().strip()
    if cmd:
        write_terminal(f"> {cmd}")
        run_command(cmd)
        command_entry.delete(0, tk.END)

run_btn = tk.Button(input_frame, text="Run", command=run_from_entry)
run_btn.pack(side="right", padx=5)

# Enter запускает команду
command_entry.bind("<Return>", run_from_entry)

# ====== TRAFFIC UPDATE ======
def update_traffic():
    stats = psutil.net_io_counters(pernic=True)
    if ADAPTER_NAME in stats:
        sent = stats[ADAPTER_NAME].bytes_sent / (1024*1024)
        recv = stats[ADAPTER_NAME].bytes_recv / (1024*1024)
        traffic_label.config(text=f"Sent: {sent:.2f} MB | Received: {recv:.2f} MB")
    root.after(1000, update_traffic)

# ====== START ======
update_indicator()
update_traffic()

root.mainloop()
