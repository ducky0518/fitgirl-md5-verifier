# FitGirl MD5 File Verifier

A simple, user-friendly desktop application built with Python and CustomTkinter to recursively find and verify MD5 checksums for FitGirl Repacks.

![Screenshot of FitGirl MD5 Verifier App](https://i.imgur.com/your-screenshot-url.png) <!-- It's recommended to add a screenshot of your app here -->

## Description

This application is designed to automate the process of checking file integrity. It scans a selected directory and all of its subdirectories for `.md5` checksum files. For each `.md5` file found, it reads the contents and compares the listed MD5 hashes against the actual calculated hashes of the corresponding files.

This is particularly useful for verifying large downloads, such as software packages or game files from sources like FitGirl Repacks, which often come with `.md5` files to ensure they were not corrupted during download.

## Features

-   **Recursive Scanning:** Automatically searches through all subdirectories of a chosen root folder.
-   **Full Path Logging:** Clearly displays the full path of the `.md5` file being processed and each file being verified for unambiguous results.
-   **Status Updates:** A real-time status bar shows which file is currently being processed.
-   **Graceful Stop:** A "Stop" button allows the user to safely interrupt the verification process at any time.
-   **Detailed Final Summary:** At the end of the process, a comprehensive summary is provided, detailing:
    -   Total files checked
    -   Successful verifications
    -   Failed verifications (hash mismatch)
    -   Missing files
    -   Files that could not be read (Read Errors)
-   **Modern UI:** Built with `customtkinter` for a clean, modern look that adapts to system light/dark modes.

## No requirements needed for Windows binary
-   Download from releases
  
## Installation (for non-prebuilt binary)

-   Python 3.x
-   `customtkinter` library

1.  **Save the script:** Save the Python code as a file, for example `fitgirl_verifier.py`.
2.  **Install the required library:** Open your terminal or command prompt and run the following command:
    ```bash
    pip install customtkinter
    ```

## How to Use

1.  **Run the application:** (double click pre-built Windows binary) - OR -
    ```bash
    python fitgirl_verifier.py
    ```
2.  **Select a Directory:** Click the **"Browse..."** button and choose the root directory you want to scan (e.g., the folder containing your downloaded files and the `.md5` file).
3.  **Start Verification:** Click the **"Start Verification"** button to begin the process.
4.  **Monitor Progress:**
    -   The main text area will populate with real-time logs.
    -   The progress bar indicates the overall progress through the found `.md5` files.
    -   The status bar at the bottom shows the file currently being verified.
5.  **Stop (Optional):** If you need to stop the process, click the **"Stop"** button. The application will finish its current file check and then halt.
6.  **Review Results:** Once the process is finished (or stopped), review the logs and the final summary at the bottom of the text window to see the results.

## Understanding the Log Output

-   `Processing: [path\to\file.md5]`: Indicates the application has started parsing this `.md5` file.
-   `  - OK    : [path\to\verified_file.bin]`: The file exists and its MD5 hash matches the one in the `.md5` file.
-   `  - FAILED: [path\to\verified_file.bin]`: The file exists, but its calculated MD5 hash **does not match** the expected hash.
-   `  - MISSING: [path\to\verified_file.bin]`: The file listed in the `.md5` file could not be found at the specified path.
-   `  - ERROR: Could not read file...`: The application was unable to open or read the file, which could be due to permissions issues or file corruption.
-   `  - WARN: Malformed line...`: A line in the `.md5` file did not follow the `hash *filename` format and was skipped.
