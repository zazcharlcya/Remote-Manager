# **Remote Manager**

**Remote Manager** is a desktop application for remote management and monitoring of computers on a local network. The program combines a **TCP server** and a **PySide6 graphical user interface**, allowing you to connect to other clients, exchange commands, and retrieve system information.

## **✨ Features**

* 🚀 Spin up a local TCP server to accept connections.  
* 📡 Exchange data using the JSON protocol with a message-length header (for safe transmission).  
* 💻 Retrieve system information:  
  * CPU, memory, and network usage (via psutil),  
  * OS and hardware details (via platform).  
* 🔑 Generate secret keys (via secrets).  
* 🖥 User-friendly **Qt (PySide6)** interface:  
  * list of connected clients,  
  * control buttons,  
  * notifications and dialogs,  
  * interface animations.  
* ⚙️ Support for multiple clients via multithreading.

## **📦 Installation**

1. Clone the repository:

git clone https://github.com/zazcharlcya/Remote-Manager.git

cd Remote-Manager

2. Install dependencies:

pip install \-r requirements.txt

3. Run the application:

python remote\_manager.py

## **⚙️ Dependencies**

* Python **3.10+**  
* [PySide6](https://pypi.org/project/PySide6/) — GUI  
* [psutil](https://pypi.org/project/psutil/) — resource monitoring

The rest are standard Python libraries.

## **🚀 Usage**

1. Run the application on the host that will act as the server.  
2. Determine the local IP address (the program shows it automatically).  
3. Connect clients to the server (using the IP address and port).  
4. Active clients will appear in the GUI—you can view their information and manage them.

## **📂 Project Structure**

remote-manager/  
├── remote\_manager.py \# main code (GUI \+ server)  
├── requirements.txt \# dependencies  
└── README.md \# documentation

## **🛠 Development Roadmap**

* 🔒 Add traffic encryption (TLS).  
* 🌍 Support for internet connections.  
* 📊 More comprehensive resource metrics.  
* 🖥 Package into an .exe/.AppImage for easy launch.

## **📜 License**

MIT — feel free to use.
