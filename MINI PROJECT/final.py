import tkinter as tk
from tkinter import messagebox, Canvas, Toplevel, ttk
import json
import threading
from datetime import datetime
import matplotlib.pyplot as plt

data_file = "hospital_data.json"
discharge_file = "discharge_history.json"

def load_data():
    try:
        with open(data_file, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"users": {}, "patients": [], "beds": {"total": 10, "occupied": 0},
                "icu_beds": {"total": 5, "occupied": 0}, "patient_queue": []}

def save_data(data):
    with open(data_file, "w") as file:
        json.dump(data, file, indent=4)

def load_discharge_history():
    try:
        with open(discharge_file, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_discharge_history(history):
    with open(discharge_file, "w") as file:
        json.dump(history, file, indent=4)

data = load_data()

def register_user():
    username = entry_username.get().strip().lower()
    password = entry_password.get().strip()
    role = role_var.get()

    if not username or not password:
        return messagebox.showerror("Error", "Username and password required!")

    if username in data["users"]:
        return messagebox.showerror("Error", "Username already exists!")

    data["users"][username] = {"password": password, "role": role}
    save_data(data)
    messagebox.showinfo("Success", "User registered!")

def authenticate():
    global logged_in_role
    username = entry_username.get().strip().lower()
    password = entry_password.get().strip()

    user = data["users"].get(username)
    if user and user["password"] == password:
        logged_in_role = user["role"]
        messagebox.showinfo("Login Success", f"Logged in as {logged_in_role}")
        show_main_menu()
    else:
        messagebox.showerror("Error", "Invalid credentials!")

def admit_patient():
    if logged_in_role not in ["admin", "doctor", "nurse"]:
        return messagebox.showerror("Error", "Unauthorized access!")

    name = entry_patient.get().strip()
    priority = priority_var.get()
    if not name:
        return messagebox.showerror("Error", "Enter a name!")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data["patient_queue"].append({"name": name, "priority": priority, "timestamp": timestamp})
    emergency = [p for p in data["patient_queue"] if p["priority"] == "Emergency"]
    normal = sorted([p for p in data["patient_queue"] if p["priority"] == "Normal"], key=lambda x: x["timestamp"])
    data["patient_queue"] = emergency + normal

    while data["patient_queue"]:
        patient = data["patient_queue"].pop(0)
        info = {"name": patient["name"], "priority": patient["priority"], "timestamp": patient["timestamp"]}

        if patient["priority"] == "Emergency":
            if data["icu_beds"]["occupied"] < data["icu_beds"]["total"]:
                data["icu_beds"]["occupied"] += 1
                info["type"] = "ICU"
                data["patients"].append(info)
            else:
                messagebox.showerror("Full", "No ICU beds available.")
                return
        else:
            if data["beds"]["occupied"] < data["beds"]["total"]:
                data["beds"]["occupied"] += 1
                info["type"] = "General"
                data["patients"].append(info)
            else:
                messagebox.showerror("Full", "No general beds available.")
                return

    save_data(data)
    update_visualization()
    update_report_table()
    show_scheduling_efficiency()  # Show graph immediately after admitting
    messagebox.showinfo("Success", f"Patient '{name}' admitted!")

def discharge_patient():
    if logged_in_role not in ["admin", "doctor"]:
        return messagebox.showerror("Error", "Only Admins and Doctors can discharge.")

    top = Toplevel(root)
    top.title("Discharge Patient")
    top.geometry("400x300")
    tk.Label(top, text="Select Patient to Discharge", font=("Arial", 12)).pack()

    lb = tk.Listbox(top)
    lb.pack(fill=tk.BOTH, expand=True)

    for p in data["patients"]:
        lb.insert(tk.END, f"{p['name']} ({p['type']})")

    def discharge():
        sel = lb.curselection()
        if not sel:
            return messagebox.showerror("Error", "Select a patient!")
        idx = sel[0]
        patient = data["patients"].pop(idx)

        if patient["type"] == "ICU":
            data["icu_beds"]["occupied"] -= 1
        else:
            data["beds"]["occupied"] -= 1

        history = load_discharge_history()
        patient["discharged_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        history.append(patient)
        save_discharge_history(history)
        save_data(data)
        update_visualization()
        update_report_table()
        messagebox.showinfo("Success", f"Discharged: {patient['name']}")
        top.destroy()

    tk.Button(top, text="Discharge", command=discharge, bg="#5bc0de", fg="white").pack()

def update_visualization():
    canvas.delete("all")
    canvas.create_text(10, 10, anchor="nw", text=f"Available General Beds: {data['beds']['total'] - data['beds']['occupied']}", font=("Arial", 10, "bold"))
    canvas.create_text(10, 30, anchor="nw", text=f"Available ICU Beds: {data['icu_beds']['total'] - data['icu_beds']['occupied']}", font=("Arial", 10, "bold"))

    canvas.create_text(10, 50, anchor="nw", text="ICU Beds:", font=("Arial", 11, "bold"))
    row_limit = 5
    icu_patients = [p for p in data["patients"] if p["type"] == "ICU"]
    for i, p in enumerate(icu_patients):
        col, row = i % row_limit, i // row_limit
        bx, by = 100 * col + 10, 70 + 70 * row
        canvas.create_rectangle(bx, by, bx + 90, by + 50, fill="#66b3ff")
        canvas.create_text(bx + 45, by + 15, text=f"Bed {i + 1}", fill="white")
        canvas.create_text(bx + 45, by + 35, text=p["name"], fill="white")

    gen_start_y = 70 + 70 * ((len(icu_patients) + row_limit - 1) // row_limit) + 10
    canvas.create_text(10, gen_start_y, anchor="nw", text="General Beds:", font=("Arial", 11, "bold"))
    general_patients = [p for p in data["patients"] if p["type"] == "General"]
    for i, p in enumerate(general_patients):
        col, row = i % row_limit, i // row_limit
        bx, by = 100 * col + 10, gen_start_y + 20 + 70 * row
        canvas.create_rectangle(bx, by, bx + 90, by + 50, fill="#6699cc")
        canvas.create_text(bx + 45, by + 15, text=f"Bed {i + 1}", fill="white")
        canvas.create_text(bx + 45, by + 35, text=p["name"], fill="white")

def update_report_table():
    for row in report_tree.get_children():
        report_tree.delete(row)

    sorted_patients = sorted(data["patients"], key=lambda x: (x["priority"] == "Normal", x["timestamp"]))
    for p in sorted_patients:
        report_tree.insert("", tk.END, values=(p["name"], p["priority"], p["timestamp"], p["type"]))

def show_main_menu():
    login_frame.pack_forget()
    menu_frame.pack(fill="both", expand=True)
    update_visualization()
    update_report_table()

def logout():
    global logged_in_role
    logged_in_role = None
    menu_frame.pack_forget()
    login_frame.pack()

def show_scheduling_efficiency():
    history = load_discharge_history()
    fcfs = sum(1 for p in history if p["priority"] == "Normal")
    priority = sum(1 for p in history if p["priority"] == "Emergency")

    total = fcfs + priority if fcfs + priority > 0 else 1

    plt.figure(figsize=(6, 4))
    plt.bar(["FCFS (Normal)", "Priority (Emergency)"], [fcfs, priority], color=["skyblue", "salmon"])
    plt.title(f"VJ Vital Care - Scheduling Efficiency")
    plt.xlabel("Scheduling Method")
    plt.ylabel("Number of Patients Discharged")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.show()

# GUI SETUP
root = tk.Tk()
root.title("Hospital Bed Management System")
root.geometry("1100x600")
root.configure(bg="#f4f4f4")

logged_in_role = None

# Login Frame
login_frame = tk.Frame(root, bg="#f4f4f4")
login_frame.pack()

tk.Label(login_frame, text="VJ Vital Care", font=("Arial", 20, "bold"), bg="#f4f4f4", fg="black").pack(pady=20)

tk.Label(login_frame, text="Username:", bg="#f4f4f4").pack()
entry_username = tk.Entry(login_frame)
entry_username.pack()

tk.Label(login_frame, text="Password:", bg="#f4f4f4").pack()
entry_password = tk.Entry(login_frame, show="*")
entry_password.pack()

role_var = tk.StringVar(value="doctor")
tk.Label(login_frame, text="Role:", bg="#f4f4f4").pack()
for role in ["admin", "doctor", "nurse"]:
    tk.Radiobutton(login_frame, text=role.capitalize(), variable=role_var, value=role, bg="#f4f4f4").pack()

tk.Button(login_frame, text="Register", command=register_user, bg="#5bc0de", fg="white").pack(pady=5, fill="x")
tk.Button(login_frame, text="Login", command=authenticate, bg="#5bc0de", fg="white").pack(pady=5, fill="x")

# Main Menu
menu_frame = tk.Frame(root)

tk.Label(menu_frame, text="VJ Vital Care", font=("Arial", 20, "bold"), bg="#f4f4f4", fg="black").pack(pady=10)

left_panel = tk.Frame(menu_frame, bg="#f4f4f4")
left_panel.pack(side="left", fill="both", expand=True)

tk.Label(left_panel, text="Patient Name:", bg="#f4f4f4").pack()
entry_patient = tk.Entry(left_panel)
entry_patient.pack(pady=5)

priority_var = tk.StringVar(value="Normal")
tk.Radiobutton(left_panel, text="Normal", variable=priority_var, value="Normal", bg="#f4f4f4").pack()
tk.Radiobutton(left_panel, text="Emergency", variable=priority_var, value="Emergency", bg="#f4f4f4").pack()

button_frame = tk.Frame(left_panel, bg="#f4f4f4")
button_frame.pack(pady=10, fill="x")

button_color = "#5bc0de"
tk.Button(button_frame, text="Admit Patient", command=lambda: threading.Thread(target=admit_patient).start(),
          bg=button_color, fg="white", font=("Arial", 10, "bold"), width=15).pack(side="top", pady=5)

tk.Button(button_frame, text="Discharge Patient", command=discharge_patient,
          bg=button_color, fg="white", font=("Arial", 10, "bold"), width=15).pack(side="top", pady=5)

tk.Button(button_frame, text="View Scheduling Graph", command=show_scheduling_efficiency,
          bg=button_color, fg="white", font=("Arial", 10, "bold"), width=20).pack(side="top", pady=5)

tk.Button(button_frame, text="Logout", command=logout,
          bg=button_color, fg="white", font=("Arial", 10, "bold"), width=15).pack(side="top", pady=5)

canvas = Canvas(left_panel, width=600, height=400, bg="white")
canvas.pack(pady=10)

right_panel = tk.Frame(menu_frame, bg="#f4f4f4")
right_panel.pack(side="right", fill="y", padx=5)

tk.Label(right_panel, text="Admission Report", font=("Arial", 12, "bold"), bg="#f4f4f4").pack()
columns = ("Name", "Priority", "Timestamp", "Type")
report_tree = ttk.Treeview(right_panel, columns=columns, show="headings", height=24)
for col in columns:
    report_tree.heading(col, text=col)
    report_tree.column(col, width=100)
report_tree.pack()

root.mainloop()
