import customtkinter as ctk
from tkinter import filedialog, ttk
import os
import hashlib
import threading

# Set the appearance mode and default color theme
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

class MD5VerifierApp(ctk.CTk):
    """
    A CustomTkinter application to recursively find .md5 files in a directory
    and verify the checksums of the corresponding files.
    """
    def __init__(self):
        super().__init__()

        # --- Window Setup ---
        self.title("FitGirl MD5 File Verifier (by -God-like)")
        self.geometry("800x600")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- State Variables ---
        self.selected_directory = ctk.StringVar()
        self.is_running = False
        self.stop_event = threading.Event() # For safely stopping the thread

        # --- Summary Counters ---
        self.files_ok = 0
        self.files_failed = 0
        self.files_missing = 0
        self.read_errors = 0

        # --- Widgets ---
        self.create_widgets()

    def create_widgets(self):
        """Creates and places all the GUI widgets in the window."""
        # --- Frame for Directory Selection ---
        top_frame = ctk.CTkFrame(self)
        top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        top_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top_frame, text="Directory:").grid(row=0, column=0, padx=10, pady=10)
        self.dir_entry = ctk.CTkEntry(top_frame, textvariable=self.selected_directory, state="readonly")
        self.dir_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        self.browse_button = ctk.CTkButton(top_frame, text="Browse...", command=self.browse_directory)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10)

        # --- Frame for Control Buttons and Progress ---
        control_frame = ctk.CTkFrame(self)
        control_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        control_frame.grid_columnconfigure((0, 1), weight=1) # Configure two columns

        self.start_button = ctk.CTkButton(control_frame, text="Start Verification", command=self.start_verification_thread)
        self.start_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # Add the Stop button
        self.stop_button = ctk.CTkButton(control_frame, text="Stop", command=self.stop_verification, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.progress_bar = ctk.CTkProgressBar(control_frame, orientation="horizontal")
        self.progress_bar.set(0)
        self.progress_bar.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        # --- Textbox for Results ---
        self.results_textbox = ctk.CTkTextbox(self, state="disabled", font=("Courier", 12))
        self.results_textbox.grid(row=2, column=0, padx=10, pady=(0,10), sticky="nsew")

        # --- Status Bar ---
        self.status_label = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.status_label.grid(row=3, column=0, padx=10, pady=5, sticky="ew")


    def browse_directory(self):
        """Opens a dialog to select a directory."""
        directory = filedialog.askdirectory()
        if directory:
            self.selected_directory.set(directory)
            self.status_label.configure(text=f"Selected: {directory}")
            self.log_message(f"Selected directory: {directory}\n", clear=True)

    def log_message(self, message, clear=False):
        """Logs a message to the results textbox."""
        self.results_textbox.configure(state="normal")
        if clear:
            self.results_textbox.delete("1.0", ctk.END)
        self.results_textbox.insert(ctk.END, message)
        self.results_textbox.configure(state="disabled")
        self.results_textbox.see(ctk.END) # Auto-scroll

    def start_verification_thread(self):
        """Starts the verification process in a separate thread to avoid freezing the GUI."""
        if self.is_running:
            self.log_message("Verification is already in progress.\n")
            return

        directory = self.selected_directory.get()
        if not directory:
            self.log_message("Please select a directory first.\n", clear=True)
            self.status_label.configure(text="Error: No directory selected.")
            return

        # Reset counters for the new run
        self.files_ok = 0
        self.files_failed = 0
        self.files_missing = 0
        self.read_errors = 0

        self.is_running = True
        self.stop_event.clear()
        self.start_button.configure(state="disabled", text="Running...")
        self.stop_button.configure(state="normal")
        self.browse_button.configure(state="disabled")
        self.progress_bar.set(0)
        self.log_message(f"Starting verification in '{directory}'...\n\n", clear=True)

        thread = threading.Thread(target=self.run_verification, args=(directory,))
        thread.daemon = True
        thread.start()

    def stop_verification(self):
        """Signals the verification thread to stop."""
        if self.is_running:
            self.log_message("\n*** STOP signal received. Finishing current task and stopping... ***\n")
            self.update_status("Stopping...")
            self.stop_event.set()
            self.stop_button.configure(state="disabled")

    def run_verification(self, root_directory):
        """The core logic for finding and verifying MD5 files."""
        try:
            md5_files = []
            for dirpath, _, filenames in os.walk(root_directory):
                if self.stop_event.is_set(): break
                for filename in filenames:
                    if self.stop_event.is_set(): break
                    if filename.lower().endswith(".md5"):
                        md5_files.append(os.path.join(dirpath, filename))

            if not md5_files and not self.stop_event.is_set():
                self.log_message("No .md5 files found in the selected directory or its subdirectories.\n")
                self.update_status("Finished: No .md5 files found.")
                return

            if not self.stop_event.is_set():
                self.log_message(f"Found {len(md5_files)} MD5 file(s). Starting checks...\n{'='*40}\n")
            
            total_md5_files = len(md5_files)
            files_processed = 0

            for md5_file_path in md5_files:
                if self.stop_event.is_set(): break
                self.log_message(f"Processing: {md5_file_path}\n")
                self.verify_single_md5_file(md5_file_path)
                files_processed += 1
                progress = files_processed / total_md5_files if total_md5_files > 0 else 0
                self.progress_bar.set(progress)

        except Exception as e:
            self.log_message(f"\nAn unexpected error occurred: {e}\n")
            self.update_status(f"Error: {e}")
        finally:
            self.is_running = False
            self.start_button.configure(state="normal", text="Start Verification")
            self.browse_button.configure(state="normal")
            self.stop_button.configure(state="disabled")

            # --- Generate and log the final summary ---
            total_processed = self.files_ok + self.files_failed + self.files_missing + self.read_errors
            summary_lines = [
                f"\n{'='*40}",
                "Verification Summary:",
                f"  - Total Files Checked: {total_processed}",
                f"  - Successful:          {self.files_ok}",
                f"  - Failed (Mismatch):   {self.files_failed}",
                f"  - Missing:             {self.files_missing}",
                f"  - Read Errors:         {self.read_errors}",
                f"{'='*40}\n"
            ]
            summary_text = "\n".join(summary_lines)
            self.log_message(summary_text)

            if self.stop_event.is_set():
                self.log_message("Verification stopped by user.\n")
                self.update_status("Verification stopped.")
            else:
                self.log_message("Verification finished.\n")
                self.update_status("Verification complete.")


    def verify_single_md5_file(self, md5_file_path):
        """
        Parses a single .md5 file and verifies each file listed within it.
        Increments summary counters.
        """
        base_dir = os.path.dirname(md5_file_path)
        try:
            with open(md5_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line in lines:
                if self.stop_event.is_set(): return

                line = line.strip()
                if line.startswith(';') or not line: continue

                parts = line.split('*')
                if len(parts) != 2:
                    self.log_message(f"  - WARN: Malformed line, skipping: '{line}'\n")
                    continue

                expected_md5 = parts[0].strip().lower()
                relative_path_part = parts[1].strip()
                
                target_file_path = os.path.normpath(os.path.join(base_dir, relative_path_part))

                if os.path.exists(target_file_path):
                    self.update_status(f"Verifying: {target_file_path}")
                    actual_md5 = self.calculate_md5(target_file_path)
                    if self.stop_event.is_set(): return
                    
                    if actual_md5 is None:
                        self.read_errors += 1
                        continue
                    
                    if actual_md5 == expected_md5:
                        self.log_message(f"  - OK    : {target_file_path}\n")
                        self.files_ok += 1
                    else:
                        self.log_message(f"  - FAILED: {target_file_path}\n")
                        self.log_message(f"    - Expected: {expected_md5}\n")
                        self.log_message(f"    - Actual  : {actual_md5}\n")
                        self.files_failed += 1
                else:
                    self.log_message(f"  - MISSING: {target_file_path}\n")
                    self.update_status(f"File not found: {os.path.basename(target_file_path)}")
                    self.files_missing += 1
            self.log_message("-" * 20 + "\n")
        except Exception as e:
            self.log_message(f"  - ERROR: Could not process file {md5_file_path}. Reason: {e}\n")

    def calculate_md5(self, file_path, block_size=65536):
        """Calculates the MD5 hash of a file."""
        md5 = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                while True:
                    if self.stop_event.is_set(): return None
                    block = f.read(block_size)
                    if not block: break
                    md5.update(block)
            return md5.hexdigest().lower()
        except (IOError, OSError) as e:
            self.log_message(f"  - ERROR: Could not read file {file_path}. Reason: {e}\n")
            return None
            
    def update_status(self, text):
        """Updates the status bar label."""
        self.status_label.configure(text=text)


if __name__ == "__main__":
    app = MD5VerifierApp()
    app.mainloop()
