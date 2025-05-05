# Wake On LAN & Device Management Tool

## Description

This application provides a graphical user interface (GUI) built with PyQt5 to manage network devices. It allows users to:
*   Send Wake-on-LAN (WOL) magic packets to wake up devices.
*   Add, edit, and delete device information (Name, MAC Address, IP Address, OS, SSH credentials).
*   Scan the local network to discover active devices.
*   Check the online status of registered devices using ping.
*   Remotely shut down or restart devices via SSH (supports Windows and Linux).

Device information is stored locally in a `devices.json` file.

## Features

*   **Wake-on-LAN:** Send magic packets to wake devices remotely.
*   **Device Management:** Maintain a list of network devices with relevant details.
*   **Network Scanning:** Discover devices on the local network within a specified IP range.
*   **Status Checking:** Periodically check if registered devices are online or offline.
*   **Remote Control (SSH):**
    *   Shutdown Windows/Linux devices.
    *   Restart Windows/Linux devices.
*   **Modern GUI:** User-friendly interface built with PyQt5.

## Requirements

*   Python 3.x
*   PyQt5
*   paramiko

## Installation

1.  **Clone the repository or download the files.**
2.  **Install the required Python libraries:**
    ```bash
    pip install PyQt5 paramiko
    ```

## Usage

1.  Ensure you have Python and the required libraries installed.
2.  Run the application from your terminal:
    ```bash
    python main.py
    ```
3.  The application window will open. You can add devices manually or use the network scan feature.

## Configuration

*   Device details are stored in the `devices.json` file in the same directory as the script. This file is created automatically when you add the first device.
*   For SSH functionality (shutdown/restart), you need to provide the IP address, SSH username, and either a password or a path to a valid SSH private key file for the target device. Ensure the target device has SSH enabled and configured correctly. For Linux commands requiring `sudo`, ensure the SSH user has appropriate permissions (e.g., passwordless sudo).

## Dependencies

*   `sys`
*   `socket`
*   `struct`
*   `re`
*   `json`
*   `os`
*   `subprocess`
*   `paramiko`
*   `PyQt5`
