import os
import time
import hashlib
import logging
import requests
import threading
import smtplib
import tkinter as tk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tkinter import filedialog, scrolledtext, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    filename='file_system_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

VIRUSTOTAL_API_KEY = "f5f8efc4a318e8ae9dc400f137b3fc6167b9892f67e4c7068bac3d5ad5022f1d"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"  # Change if using another email provider
SMTP_PORT = 587
SENDER_EMAIL = "karanshinde0509@gmail.com"  # Replace with your email
SENDER_PASSWORD = "karan0509@"  # Replace with your email password
RECEIVER_EMAIL = "tommmmy4200@gmail.com"  # Replace with the recipient email

def send_email_alert(file_path):
    try:
        username = os.getlogin()  # Get the logged-in username
        subject = "Malicious File Detected!"
        body = f"A malicious file has been detected and deleted.\n\nFile: {file_path}\nUser: {username}"

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        log_message(f"Email alert sent successfully for {file_path}")
    except Exception as e:
        log_message(f"Error sending email alert: {e}")

class MaliciousActivityHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            md5_hash = generate_md5(event.src_path)
            log_message(f"File created: {event.src_path} | MD5: {md5_hash}")
            if md5_hash:
                is_malicious = check_virustotal(md5_hash)
                if is_malicious:
                    log_message(f"Malicious file detected: {event.src_path}. Deleting...", color="red")
                    send_email_alert(event.src_path)
                    delete_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            md5_hash = generate_md5(event.src_path)
            log_message(f"File modified: {event.src_path} | MD5: {md5_hash}")
            if md5_hash:
                is_malicious = check_virustotal(md5_hash)
                if is_malicious:
                    log_message(f"Malicious file detected: {event.src_path}. Deleting...", color="red")
                    send_email_alert(event.src_path)
                    delete_file(event.src_path)

def generate_md5(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            return hashlib.md5(file_data).hexdigest()
    except Exception as e:
        log_message(f"Error generating MD5 for {file_path}: {e}")
        return None

def check_virustotal(md5_hash):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"{VIRUSTOTAL_API_URL}/{md5_hash}", headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        if 'data' in json_response and 'attributes' in json_response['data']:
            malicious = json_response['data']['attributes']['last_analysis_stats']['malicious']
            return malicious > 0
    log_message(f"VirusTotal API Error: {response.status_code} - {response.text}")
    return None

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            log_message(f"Deleted malicious file: {file_path}", color="red")
        else:
            log_message(f"File not found: {file_path}")
    except Exception as e:
        log_message(f"Error deleting file {file_path}: {e}")

def log_message(message, color="black"):
    logging.info(message)
    log_display.insert(tk.END, message + "\n", color)
    log_display.yview(tk.END)
    log_display.tag_config("red", foreground="red")

class FileMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Monitoring System")
        self.root.geometry("800x500")
        self.root.configure(bg="#f0f0f0")

        self.directory_path = tk.StringVar()
        tk.Label(root, text="Directory to Monitor:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        self.path_entry = tk.Entry(root, textvariable=self.directory_path, width=60, state="readonly", font=("Arial", 10))
        self.path_entry.pack(pady=5)
        tk.Button(root, text="Select Directory", font=("Arial", 10), command=self.select_directory).pack(pady=5)

        self.start_button = tk.Button(root, text="Start Monitoring", font=("Arial", 12), command=self.start_monitoring, bg="green", fg="white")
        self.start_button.pack(pady=5)
        self.stop_button = tk.Button(root, text="Stop Monitoring", font=("Arial", 12), command=self.stop_monitoring, bg="red", fg="white", state="disabled")
        self.stop_button.pack(pady=5)

        tk.Label(root, text="Log Output:", font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        global log_display
        log_display = scrolledtext.ScrolledText(root, width=90, height=15, state="normal", font=("Arial", 10))
        log_display.pack(pady=5)

        self.status_label = tk.Label(root, text="Status: Not Monitoring", font=("Arial", 12, "bold"), fg="red", bg="#f0f0f0")
        self.status_label.pack(pady=5)

        self.monitoring = False
        self.observer = None

    def select_directory(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.directory_path.set(folder_selected)

    def start_monitoring(self):
        if not self.directory_path.get():
            messagebox.showwarning("Warning", "Please select a directory first!")
            return

        self.monitoring = True
        self.status_label.config(text="Status: Monitoring", fg="green")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.monitor_thread = threading.Thread(target=self.run_monitor, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.status_label.config(text="Status: Not Monitoring", fg="red")
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

    def run_monitor(self):
        event_handler = MaliciousActivityHandler()
        self.observer = Observer()
        self.observer.schedule(event_handler, self.directory_path.get(), recursive=True)
        self.observer.start()

        try:
            while self.monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileMonitorApp(root)
    root.mainloop()

