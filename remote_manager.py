import sys
import socket
import json
import threading
import psutil
import platform
import secrets
import struct
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton,
    QLabel, QMessageBox, QInputDialog, QLineEdit
)
from PySide6.QtCore import QPropertyAnimation, QEasingCurve, Qt, QTimer
from PySide6.QtGui import QIcon, QFont

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

class ServerThread(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            while self.running:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def send_json(self, conn, obj):
        data = json.dumps(obj).encode('utf-8')
        length = struct.pack('>I', len(data))
        conn.sendall(length + data)

    def recv_json(self, conn):
        # Сначала читаем 4 байта длины
        raw_len = self._recvall(conn, 4)
        if not raw_len:
            return None
        msglen = struct.unpack('>I', raw_len)[0]
        data = self._recvall(conn, msglen)
        if not data:
            return None
        try:
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f'Ошибка парсинга JSON: {e}')
            return None

    def _recvall(self, conn, n):
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def handle_client(self, conn):
        try:
            while True:
                request = self.recv_json(conn)
                if not request:
                    break
                action = request.get('action')
                if action == 'processes':
                    procs = []
                    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
                        try:
                            procs.append({
                                'pid': p.info['pid'],
                                'name': p.info['name'],
                                'user': p.info['username'],
                                'cpu': p.info['cpu_percent'],
                                'mem': p.info['memory_info'].rss // 1024 // 1024
                            })
                        except Exception:
                            continue
                    self.send_json(conn, {'processes': procs})
                elif action == 'kill':
                    pid = request.get('pid')
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        p.wait(timeout=3)
                        self.send_json(conn, {'status': 'killed'})
                    except Exception as e:
                        self.send_json(conn, {'error': f'Ошибка: {e}'})
                elif action == 'sysinfo':
                    info = {
                        'platform': platform.platform(),
                        'cpu_count': psutil.cpu_count(),
                        'cpu_percent': psutil.cpu_percent(),
                        'ram_total': psutil.virtual_memory().total // 1024 // 1024,
                        'ram_used': psutil.virtual_memory().used // 1024 // 1024,
                        'ram_percent': psutil.virtual_memory().percent
                    }
                    self.send_json(conn, {'sysinfo': info})
                else:
                    self.send_json(conn, {'error': 'Unknown action'})
        finally:
            conn.close()

class ServerThreadWithPassword(ServerThread):
    def __init__(self, host, port, password):
        super().__init__(host, port)
        self.password = password

    def handle_client(self, conn):
        try:
            while True:
                request = self.recv_json(conn)
                if not request:
                    break
                if request.get('password') != self.password:
                    self.send_json(conn, {'error': 'Неверный пароль'})
                    continue
                action = request.get('action')
                if action == 'processes':
                    procs = []
                    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
                        try:
                            procs.append({
                                'pid': p.info['pid'],
                                'name': p.info['name'],
                                'user': p.info['username'],
                                'cpu': p.info['cpu_percent'],
                                'mem': p.info['memory_info'].rss // 1024 // 1024
                            })
                        except Exception:
                            continue
                    self.send_json(conn, {'processes': procs})
                elif action == 'kill':
                    pid = request.get('pid')
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        p.wait(timeout=3)
                        self.send_json(conn, {'status': 'killed'})
                    except Exception as e:
                        self.send_json(conn, {'error': f'Ошибка: {e}'})
                elif action == 'kill_by_name':
                    name = request.get('name')
                    killed = 0
                    for p in psutil.process_iter(['name']):
                        if p.info['name'] == name:
                            try:
                                p.terminate()
                                killed += 1
                            except Exception:
                                continue
                    self.send_json(conn, {'status': f'Завершено процессов: {killed}'})
                elif action == 'kill_user':
                    user = request.get('user')
                    killed = 0
                    for p in psutil.process_iter(['username']):
                        if p.info['username'] == user:
                            try:
                                p.terminate()
                                killed += 1
                            except Exception:
                                continue
                    self.send_json(conn, {'status': f'Завершено процессов пользователя: {killed}'})
                elif action == 'sysinfo':
                    info = {
                        'platform': platform.platform(),
                        'cpu_count': psutil.cpu_count(),
                        'cpu_percent': psutil.cpu_percent(),
                        'ram_total': psutil.virtual_memory().total // 1024 // 1024,
                        'ram_used': psutil.virtual_memory().used // 1024 // 1024,
                        'ram_percent': psutil.virtual_memory().percent,
                        'disks': [
                            {
                                'device': d.device,
                                'mountpoint': d.mountpoint,
                                'fstype': d.fstype,
                                'total': psutil.disk_usage(d.mountpoint).total // 1024 // 1024,
                                'used': psutil.disk_usage(d.mountpoint).used // 1024 // 1024,
                                'free': psutil.disk_usage(d.mountpoint).free // 1024 // 1024,
                                'percent': psutil.disk_usage(d.mountpoint).percent
                            } for d in psutil.disk_partitions() if d.fstype
                        ]
                    }
                    self.send_json(conn, {'sysinfo': info})
                else:
                    self.send_json(conn, {'error': 'Unknown action'})
        finally:
            conn.close()

class AnimatedWindow(QWidget):
    def showEvent(self, event):
        self.setWindowOpacity(0)
        anim = QPropertyAnimation(self, b"windowOpacity")
        anim.setDuration(700)
        anim.setStartValue(0)
        anim.setEndValue(1)
        anim.setEasingCurve(QEasingCurve.OutExpo)
        anim.start()
        self._anim = anim
        super().showEvent(event)

class ServerWindow(AnimatedWindow):
    def __init__(self, host, port, password):
        super().__init__()
        self.setWindowTitle(f"🖥️ SERVER DASHBOARD | {host}:{port}")
        self.setWindowIcon(QIcon.fromTheme("computer"))
        self.setMinimumSize(600, 400)
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f2027, stop:0.5 #2c5364, stop:1 #232526);
                color: #e0e6ed;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 20px;
            }
            QLabel#title {
                color: #00e6d8;
                font-size: 32px;
                font-weight: 800;
                letter-spacing: 2px;
                margin-bottom: 18px;
            }
            QLabel#sysinfo {
                color: #fff;
                font-size: 19px;
                font-weight: 500;
                background: rgba(0,0,0,0.25);
                border-radius: 12px;
                padding: 18px 24px;
                margin-bottom: 18px;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00e6d8, stop:1 #0072ff);
                border-radius: 16px;
                padding: 14px 32px;
                color: #232526;
                font-size: 20px;
                font-weight: 700;
                box-shadow: 0 6px 24px #00e6d855;
                margin-top: 10px;
                margin-bottom: 10px;
                transition: background 0.3s;
            }
            QPushButton:hover {
                background: #fff;
                color: #00e6d8;
            }
        """)
        layout = QVBoxLayout(self)
        title = QLabel("SERVER DASHBOARD")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        info = QLabel(f"<b>IP:</b> {host}   <b>PORT:</b> {port}   <b>Пароль:</b> {password}")
        info.setAlignment(Qt.AlignCenter)
        info.setStyleSheet("color:#b2becd;font-size:18px;margin-bottom:10px;")
        layout.addWidget(info)
        self.sysinfo_label = QLabel()
        self.sysinfo_label.setObjectName("sysinfo")
        layout.addWidget(self.sysinfo_label)
        self.update_sysinfo()
        self.refresh_btn = QPushButton("Обновить информацию о системе")
        self.refresh_btn.setToolTip("Обновить данные о системе")
        self.refresh_btn.clicked.connect(self.update_sysinfo)
        layout.addWidget(self.refresh_btn)
    def update_sysinfo(self):
        info = {
            'Платформа': platform.platform(),
            'CPU ядер': psutil.cpu_count(),
            'CPU загрузка': psutil.cpu_percent(),
            'RAM всего (MB)': psutil.virtual_memory().total // 1024 // 1024,
            'RAM занято (MB)': psutil.virtual_memory().used // 1024 // 1024,
            'RAM %': psutil.virtual_memory().percent
        }
        text = "\n".join(f"{k}: {v}" for k, v in info.items())
        self.sysinfo_label.setText(text)

class TaskManagerClient(AnimatedWindow):
    def __init__(self, server_host, server_port, password, is_local=False):
        super().__init__()
        self.setWindowTitle("Task Manager | Client")
        self.setWindowIcon(QIcon.fromTheme("system-run"))
        self.setMinimumSize(950, 700)
        self.setStyleSheet("""
            QWidget {
                background: #181c20;
                color: #e0e6ed;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 18px;
            }
            QLabel#title {
                color: #7ecfff;
                font-size: 32px;
                font-weight: 900;
                letter-spacing: 2px;
                margin-bottom: 18px;
                text-shadow: 0 2px 8px #222a33;
            }
            QLabel#sysinfo {
                color: #b2becd;
                font-size: 17px;
                font-weight: 500;
                background: #23272e;
                border-radius: 14px;
                padding: 16px 22px;
                margin-bottom: 18px;
                box-shadow: 0 2px 12px #0006;
            }
            QPushButton {
                background: #23272e;
                border-radius: 12px;
                padding: 10px 22px;
                color: #e0e6ed;
                font-size: 17px;
                font-weight: 600;
                margin: 6px;
                border: 1.5px solid #2e3440;
                transition: background 0.2s, color 0.2s;
            }
            QPushButton:hover {
                background: #31363f;
                color: #7ecfff;
                border: 1.5px solid #7ecfff;
            }
            QListWidget {
                background: #23272e;
                border-radius: 12px;
                font-size: 16px;
                color: #e0e6ed;
                padding: 8px;
                border: 1.5px solid #2e3440;
            }
            QLineEdit {
                background: #23272e;
                color: #e0e6ed;
                border-radius: 10px;
                padding: 8px 14px;
                font-size: 16px;
                margin-bottom: 10px;
                border: 1.5px solid #2e3440;
            }
        """)
        layout = QVBoxLayout(self)
        title = QLabel("TASK MANAGER CLIENT")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        self.server_host = server_host
        self.server_port = server_port
        self.is_local = is_local
        self.password = password
        self.sysinfo_label = QLabel()
        self.sysinfo_label.setObjectName("sysinfo")
        layout.addWidget(self.sysinfo_label)
        self.update_sysinfo()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск процесса по имени...")
        self.search_input.textChanged.connect(self.filter_processes)
        layout.addWidget(self.search_input)
        self.proc_list = QListWidget()
        layout.addWidget(self.proc_list)
        # --- Кнопки ---
        main_btn_panel = QHBoxLayout()
        self.refresh_btn = QPushButton("🔄 Обновить процессы")
        self.refresh_btn.setToolTip("Обновить список процессов на сервере")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        main_btn_panel.addWidget(self.refresh_btn)
        self.kill_btn = QPushButton("⛔ Завершить процесс")
        self.kill_btn.setToolTip("Завершить выбранный процесс на сервере")
        self.kill_btn.clicked.connect(self.kill_process)
        main_btn_panel.addWidget(self.kill_btn)
        self.kill_by_name_btn = QPushButton("⛔ Завершить по имени")
        self.kill_by_name_btn.setToolTip("Завершить все процессы с этим именем")
        self.kill_by_name_btn.clicked.connect(self.kill_by_name)
        main_btn_panel.addWidget(self.kill_by_name_btn)
        layout.addLayout(main_btn_panel)
        # Вторая строка кнопок
        second_btn_panel = QHBoxLayout()
        # self.kill_user_btn = QPushButton("⛔ Завершить все пользователя")
        # self.kill_user_btn.setToolTip("Завершить все процессы выбранного пользователя")
        # self.kill_user_btn.clicked.connect(self.kill_user)
        # second_btn_panel.addWidget(self.kill_user_btn)
        self.copy_btn = QPushButton("📋 Копировать инфо")
        self.copy_btn.setToolTip("Копировать информацию о процессе")
        self.copy_btn.clicked.connect(self.copy_process_info)
        second_btn_panel.addWidget(self.copy_btn)
        self.about_btn = QPushButton("ℹ️ О программе")
        self.about_btn.clicked.connect(self.show_about)
        second_btn_panel.addWidget(self.about_btn)
        layout.addLayout(second_btn_panel)
        self.all_procs = []
        self.refresh_processes()
        # Автообновление процессов
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(3000)

    def send_request(self, req):
        req['password'] = self.password
        try:
            with socket.create_connection((self.server_host, self.server_port), timeout=2) as sock:
                data = json.dumps(req).encode('utf-8')
                length = struct.pack('>I', len(data))
                sock.sendall(length + data)
                # Сначала читаем 4 байта длины
                raw_len = self._recvall(sock, 4)
                if not raw_len:
                    raise Exception('Нет ответа от сервера (длина)')
                msglen = struct.unpack('>I', raw_len)[0]
                data = self._recvall(sock, msglen)
                if not data:
                    raise Exception('Нет ответа от сервера (данные)')
                return json.loads(data.decode('utf-8'))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Нет соединения с сервером: {e}")
            return None

    def _recvall(self, sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def update_sysinfo(self):
        resp = self.send_request({'action': 'sysinfo'})
        if not resp or 'sysinfo' not in resp:
            self.sysinfo_label.setText('Не удалось получить информацию о системе')
            return
        info = resp['sysinfo']
        text = f"Платформа: {info['platform']}\nCPU ядер: {info['cpu_count']}\nCPU загрузка: {info['cpu_percent']}%\nRAM всего: {info['ram_total']} MB\nRAM занято: {info['ram_used']} MB ({info['ram_percent']}%)"
        if 'disks' in info:
            text += "\n\nДиски:\n"
            for d in info['disks']:
                text += f"{d['device']} ({d['mountpoint']}): {d['used']}MB / {d['total']}MB ({d['percent']}%) свободно: {d['free']}MB\n"
        self.sysinfo_label.setText(text)

    def refresh_processes(self):
        resp = self.send_request({'action': 'processes'})
        self.all_procs = resp['processes'] if resp and 'processes' in resp else []
        self.filter_processes()

    def filter_processes(self):
        text = self.search_input.text().lower()
        self.proc_list.clear()
        self.procs = []
        for p in self.all_procs:
            if text in p['name'].lower():
                self.procs.append(p)
                self.proc_list.addItem(f"PID: {p['pid']} | {p['name']} | CPU: {p['cpu']}% | RAM: {p['mem']} MB | User: {p['user']}")

    def kill_process(self):
        row = self.proc_list.currentRow()
        if row < 0:
            QMessageBox.critical(self, "Ошибка", "Выберите процесс для завершения!")
            return
        pid = self.procs[row]['pid']
        resp = self.send_request({'action': 'kill', 'pid': pid})
        if resp and resp.get('status') == 'killed':
            QMessageBox.information(self, "Успех", f"Процесс {pid} завершён!")
            self.refresh_processes()
        elif resp and resp.get('error'):
            QMessageBox.critical(self, "Ошибка", resp['error'])

    def kill_by_name(self):
        name, ok = QInputDialog.getText(self, "Имя процесса", "Введите имя процесса:")
        if ok and name:
            resp = self.send_request({'action': 'kill_by_name', 'name': name})
            if resp and resp.get('status'):
                QMessageBox.information(self, "Успех", resp['status'])
                self.refresh_processes()
            elif resp and resp.get('error'):
                QMessageBox.critical(self, "Ошибка", resp['error'])

    def kill_user(self):
        if not self.procs:
            QMessageBox.critical(self, "Ошибка", "Нет выбранного процесса!")
            return
        user = self.procs[self.proc_list.currentRow()]['user']
        resp = self.send_request({'action': 'kill_user', 'user': user})
        if resp and resp.get('status'):
            QMessageBox.information(self, "Успех", resp['status'])
            self.refresh_processes()
        elif resp and resp.get('error'):
            QMessageBox.critical(self, "Ошибка", resp['error'])

    def copy_process_info(self):
        row = self.proc_list.currentRow()
        if row < 0:
            QMessageBox.critical(self, "Ошибка", "Выберите процесс!")
            return
        p = self.procs[row]
        info = f"PID: {p['pid']} | {p['name']} | CPU: {p['cpu']}% | RAM: {p['mem']} MB | User: {p['user']}"
        QApplication.clipboard().setText(info)
        QMessageBox.information(self, "Скопировано", "Информация о процессе скопирована в буфер обмена!")

    def show_about(self):
        QMessageBox.information(self, "О программе", "Task Manager Remote\nАвтор: zazhralcya\n2025\n\nФункции: просмотр и завершение процессов, автообновление, информация о системе и дисках, копирование инфо, современный дизайн.")

class StartWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Task Manager — выбор режима")
        self.setMinimumSize(400, 200)
        layout = QVBoxLayout(self)
        label = QLabel("Выберите режим работы:")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        btn_server = QPushButton("Сервер (управлять этим ПК)")
        btn_client = QPushButton("Клиент (подключиться к другому ПК)")
        layout.addWidget(btn_server)
        layout.addWidget(btn_client)
        self.info_label = QLabel("")
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)
        btn_server.clicked.connect(self.start_server)
        btn_client.clicked.connect(self.start_client)
        self.server_thread = None
        self.generated_password = None
        self.server_host = None
        self.server_port = None

    def start_server(self):
        host = get_local_ip()
        port = 65432
        password, ok = QInputDialog.getText(self, "Пароль сервера", "Введите пароль для сервера:", echo=QLineEdit.Password)
        if not ok or not password:
            QMessageBox.critical(self, "Ошибка", "Пароль не задан!")
            return
        self.generated_password = password
        self.server_host = host
        self.server_port = port
        self.server_thread = ServerThreadWithPassword(host, port, password)
        self.server_thread.start()
        self.info_label.setText(f"Сервер запущен!\nIP: {host}\nПорт: {port}\nПароль: {password}")
        self.hide()
        self.manager = ServerWindow(host, port, password)
        self.manager.show()

    def start_client(self):
        host = self.server_host or get_local_ip()
        port = self.server_port or 65432
        password = self.generated_password or ''
        # Если сервер уже был создан, подставляем пароль автоматически
        if password:
            self.hide()
            self.manager = TaskManagerClient(host, port, password, is_local=False)
            self.manager.show()
        else:
            host, ok1 = QInputDialog.getText(self, "IP сервера", "Введите IP:", text=get_local_ip())
            port, ok2 = QInputDialog.getInt(self, "Порт сервера", "Введите порт:", value=65432)
            password, ok3 = QInputDialog.getText(self, "Пароль", "Введите пароль:", echo=QLineEdit.Password)
            if ok1 and ok2 and ok3:
                self.hide()
                self.manager = TaskManagerClient(host, port, password, is_local=False)
                self.manager.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    icon = QIcon(":/icons/app_icon.png")
    app.setWindowIcon(icon)
    splash = QWidget()
    splash.setWindowFlag(Qt.FramelessWindowHint)
    splash.setAttribute(Qt.WA_TranslucentBackground)
    layout = QVBoxLayout(splash)
    label = QLabel("Task Manager")
    label.setStyleSheet("font-size: 32px; font-weight: 800; color: #00e6d8;")
    label.setAlignment(Qt.AlignCenter)
    layout.addWidget(label)
    splash.setGeometry(100, 100, 400, 300)
    splash.show()
    app.processEvents()
    window = StartWindow()
    window.show()
    splash.close()
    sys.exit(app.exec())