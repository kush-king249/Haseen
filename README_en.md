# Haseen - Advanced Firewall System

![Haseen Logo](https://via.placeholder.com/150/0000FF/FFFFFF?text=Haseen)

## Overview

The **Haseen** project aims to develop a robust and advanced firewall system that goes beyond traditional packet filtering. This system acts as a multi-layered defensive barrier, combining basic packet filtering with more sophisticated features such as Deep Packet Inspection (DPI) and an Intrusion Detection System (IDS) module. The system is designed to be scalable, making it suitable for various environments, and provides an attractive, interactive, and Arabic-localized graphical user interface for easy management and monitoring.

## Key Features

*   **Advanced Packet Filtering**: Allow or block packets based on complex rules involving IP addresses, ports, and protocols.
*   **Intrusion Detection System (IDS)**: Monitor network traffic for known attack patterns or suspicious behaviors.
*   **Deep Packet Inspection (DPI)**: Analyze packet payloads to detect embedded threats like SQL injection or XSS attacks.
*   **Application Control**: Ability to identify packets based on the application that generated them (future feature).
*   **Logging and Analysis**: Log all security events into a database for later analysis and detailed reporting.
*   **Graphical User Interface (GUI)**: An easy-to-use and interactive web interface in Arabic for system management, event monitoring, and statistics.
*   **Command Line Interface (CLI)**: Powerful tools for developers and administrators to manage the firewall from the command line.
*   **Scalability**: Modular architecture allowing easy addition of new features and modules.

## System Architecture

The Haseen system consists of several main modules working in harmony to provide comprehensive protection:

1.  **Firewall Engine**:
    *   **`core.py`**: The core logic of the firewall, managing startup, shutdown, packet processing, and system monitoring.
    *   **`packet_analyzer.py`**: Responsible for analyzing data packets, including protocol inspection, payload analysis, and suspicious pattern detection.
    *   **`ids_module.py`**: The Intrusion Detection System module, which inspects packets based on signature and behavioral rules to detect attacks.
    *   **`rules.py`**: The rules engine that applies predefined or user-added rules to allow or block packets.
    *   **`logger.py`**: The event logging system that stores all activities and alerts in files and an SQLite database.

2.  **Application Programming Interface (API)**:
    *   **`api/app.py`**: A Flask server that provides RESTful endpoints to interact with the firewall engine, allowing the GUI and CLI to control the system and retrieve data.

3.  **Graphical User Interface (GUI)**:
    *   A web application built using React, providing an attractive and interactive dashboard to display statistics, alerts, and manage rules.

4.  **Command Line Interface (CLI)**:
    *   **`cli/main.py`**: A command-line tool built using the Click library, providing commands to manage the firewall, view logs, and add/remove rules.

## Methodology

The Haseen project was developed following a modular approach to ensure scalability and maintainability. Python was chosen as the primary backend programming language due to its flexibility and rich libraries in networking and security. Flask was selected for building the API for its simplicity and flexibility, while React was used for the frontend to provide a modern and interactive user experience.

### Key Technologies and Libraries:

*   **Python**: Primary language for the backend.
*   **Flask**: Web framework for building the API.
*   **Scapy**: (Planned for future actual use) for deep packet analysis.
*   **netfilterqueue**: (Planned for future actual use) for interacting with Linux iptables rules.
*   **PyYAML**: For managing configuration and rules files.
*   **SQLite**: Lightweight database for storing logs and events.
*   **React**: JavaScript library for building the interactive GUI.
*   **Tailwind CSS / shadcn/ui**: For designing an attractive and responsive user interface.
*   **Recharts**: For creating charts and displaying statistics in the GUI.
*   **Click**: Python library for building the Command Line Interface (CLI).
*   **Rich**: For enhancing CLI output and making it more engaging.

## Setup and Running Instructions

To set up and run the Haseen project, follow these steps:

### 1. Prerequisites

Ensure the following requirements are installed on your system:

*   Python 3.8+ (3.11 preferred)
*   Node.js and npm/pnpm (for running the GUI)
*   `build-essential` (for some Python libraries that require compilation)
*   `libnetfilter-queue-dev` (for netfilterqueue library)
*   `libssl-dev` (for yara-python library)

You can install the required system packages on Ubuntu/Debian using the following commands:

```bash
sudo apt-get update
sudo apt-get install -y python3-dev python3.11-dev build-essential libnetfilter-queue-dev libssl-dev
```

### 2. Clone the Repository

```bash
git clone https://github.com/kush-king249/Haseen.git
cd Haseen
```

### 3. Backend Setup (Python Backend)

1.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install required Python libraries:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the API server (in a separate terminal):**
    ```bash
    cd api
    python3 app.py
    ```
    The server will run on `http://localhost:5000`.

### 4. Frontend Setup (React Frontend)

1.  **Navigate to the GUI folder and install dependencies:**
    ```bash
    cd gui/haseen-dashboard
    pnpm install
    ```

2.  **Run the development server (in a separate terminal):**
    ```bash
    pnpm run dev --host
    ```
    The GUI will run on `http://localhost:5173` (or a similar port).

### 5. Command Line Interface (CLI) Usage

You can use the CLI tool to interact with the firewall. Ensure the backend (API) is running.

1.  **Activate the virtual environment (if not already active):**
    ```bash
    source venv/bin/activate
    ```

2.  **CLI command examples:**
    *   **Start the firewall (monitor mode):**
        ```bash
        python3 cli/main.py start --mode=monitor
        ```
    *   **Show firewall status:**
        ```bash
        python3 cli/main.py status
        ```
    *   **Show recent logs:**
        ```bash
        python3 cli/main.py show-logs --limit 10
        ```
    *   **Add a rule to block external SSH:**
        ```bash
        python3 cli/main.py add-rule --rule-id BLOCK_SSH_EXTERNAL_CLI --name "Block External SSH (CLI)" --action block --destination-port 22 --protocol TCP
        ```
    *   **Show rules:**
        ```bash
        python3 cli/main.py show-rules
        ```

## Author

Hassan Mohamed Hassan Ahmed

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---
