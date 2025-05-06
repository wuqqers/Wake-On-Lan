import sys
import socket
import struct
import re
import json
import os
import subprocess
import paramiko
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QMessageBox, QDialog, QFormLayout, QDialogButtonBox,
                             QProgressDialog, QStyleFactory, QComboBox, QFrame,
                             QMenu, QSystemTrayIcon)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QProcess, QTimer

from PyQt5.QtGui import QColor, QIcon


with open("translations.json", "r", encoding="utf-8") as f:
    translations = json.load(f)

# 2) Kullanılan dili belirle (ör: "tr" veya "en")
current_lang = "en"  # veya "tr"

class WakeOnLAN:
    """Wake On LAN işlevselliğini sağlayan sınıf"""
    
    @staticmethod
    def send_magic_packet(mac_address, broadcast_ip='255.255.255.255', port=9):
        """
        Belirtilen MAC adresine sihirli paket gönderir
        
        Args:
            mac_address (str): Hedef cihazın MAC adresi
            broadcast_ip (str): Yayın IP adresi
            port (int): WOL portu (genellikle 7 veya 9)
        
        Returns:
            bool: İşlem başarılıysa True, değilse False
        """
        try:
            # MAC adresinden tireleri ve iki noktaları kaldır
            mac_address = mac_address.replace('-', '').replace(':', '')
            
            # MAC adresinin doğru formatta olduğunu kontrol et
            if len(mac_address) != 12:
                return False
            
            # MAC adresini byte dizisine dönüştür
            mac_bytes = bytes.fromhex(mac_address)
            
            # Magic packet: 6 byte 0xFF + 16 kez MAC adresi tekrarı
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            
            # UDP soketi oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Magic packet'i gönder
            sock.sendto(magic_packet, (broadcast_ip, port))
            sock.close()
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_mac_address(mac_address):
        """
        MAC adresinin geçerli olup olmadığını kontrol eder
        
        Args:
            mac_address (str): Kontrol edilecek MAC adresi
        
        Returns:
            bool: MAC adresi geçerliyse True, değilse False
        """
        # MAC adresini kontrol eden regex
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac_address))


class DeviceManager:
    """Cihaz listesini yöneten sınıf"""
    
    def __init__(self, config_file='devices.json'):
        """
        DeviceManager sınıfı için yapıcı
        
        Args:
            config_file (str): Cihaz bilgilerinin saklandığı dosya
        """
        self.config_file = config_file
        self.devices = self._load_devices()
    
    def _load_devices(self):
        """
        Kayıtlı cihaz listesini dosyadan yükler
        
        Returns:
            list: Cihazların listesi
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as file:
                    return json.load(file)
            return []
        except (FileNotFoundError, json.JSONDecodeError): # Daha spesifik istisnalar yakalandı
            return []
        except Exception as e: # Diğer hatalar için genel yakalama ve loglama (isteğe bağlı)
            print(f"Cihazlar yüklenirken hata oluştu: {e}")
            return []

    def _save_devices(self):
        """Cihaz listesini dosyaya kaydeder"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as file:
                json.dump(self.devices, file, indent=4)
        except IOError as e: # Daha spesifik istisna yakalandı
            print(f"Cihazlar kaydedilirken hata oluştu: {e}")
        except Exception as e: # Diğer hatalar için genel yakalama ve loglama (isteğe bağlı)
            print(f"Cihazlar kaydedilirken beklenmeyen hata oluştu: {e}")

    def add_device(self, name, mac_address, ip_address='', broadcast_ip='', os='', ssh_user='', ssh_password='', ssh_key=''):
        """
        Cihaz listesine yeni bir cihaz ekler
        
        Args:
            name (str): Cihaz adı
            mac_address (str): Cihazın MAC adresi
            ip_address (str, optional): Cihazın IP adresi
            broadcast_ip (str, optional): Cihazın broadcast IP adresi
            os (str, optional): Cihazın işletim sistemi
            ssh_user (str, optional): SSH kullanıcı adı
            ssh_password (str, optional): SSH şifresi
            ssh_key (str, optional): SSH anahtar dosya yolu
        
        Returns:
            bool: İşlem başarılıysa True, değilse False
        """
        if not WakeOnLAN.validate_mac_address(mac_address):
            return False
        
        # Aynı MAC adresiyle başka bir cihaz var mı kontrol et
        for device in self.devices:
            if device['mac_address'].lower() == mac_address.lower():
                return False
        
        # Yeni cihazı ekle
        self.devices.append({
            'name': name,
            'mac_address': mac_address,
            'ip_address': ip_address,
            'broadcast_ip': broadcast_ip, # Broadcast IP bilgisini kaydet
            'os': os, # İşletim sistemi bilgisini kaydet
            'ssh_user': ssh_user,
            'ssh_password': ssh_password,
            'ssh_key': ssh_key,
        })
        
     
        
        # Değişiklikleri kaydet
        self._save_devices()
        return True
    
    def update_device(self, index, name, mac_address, ip_address='', broadcast_ip='', os='', ssh_user='', ssh_password='', ssh_key=''):
        """
        Belirtilen indeksteki cihazı günceller
        
        Args:
            index (int): Güncellenecek cihazın indeksi
            name (str): Yeni cihaz adı
            mac_address (str): Yeni MAC adresi
            ip_address (str, optional): Yeni IP adresi
            broadcast_ip (str, optional): Yeni broadcast IP adresi
            os (str, optional): Yeni işletim sistemi
            ssh_user (str, optional): Yeni SSH kullanıcı adı
            ssh_password (str, optional): Yeni SSH şifresi
            ssh_key (str, optional): Yeni SSH anahtar dosya yolu
        
        Returns:
            bool: İşlem başarılıysa True, değilse False
        """
        if not WakeOnLAN.validate_mac_address(mac_address):
            return False
        
        if 0 <= index < len(self.devices):
            # Başka bir cihazla aynı MAC adresini kullanmadığından emin ol
            for i, device in enumerate(self.devices):
                if i != index and device['mac_address'].lower() == mac_address.lower():
                    return False
            
            # Cihazı güncelle
            self.devices[index] = {
                'name': name,
                'mac_address': mac_address,
                'ip_address': ip_address,
                'broadcast_ip': broadcast_ip, # Broadcast IP bilgisini güncelle
                'os': os, # İşletim sistemi bilgisini güncelle
                'ssh_user': ssh_user,
                'ssh_password': ssh_password,
                'ssh_key': ssh_key,
            }
            
            # Değişiklikleri kaydet
            self._save_devices()
            return True
        
        return False
        
        return False
    
    def remove_device(self, index):
        """
        Belirtilen indeksteki cihazı kaldırır
        
        Args:
            index (int): Kaldırılacak cihazın indeksi
        
        Returns:
            bool: İşlem başarılıysa True, değilse False
        """
        if 0 <= index < len(self.devices):
            self.devices.pop(index)
            self._save_devices()
            return True
        
        return False
    
    def get_device(self, index):
        """
        Belirtilen indeksteki cihazı döndürür
        
        Args:
            index (int): Alınacak cihazın indeksi
        
        Returns:
            dict: Cihaz bilgileri, bulunamazsa None
        """
        if 0 <= index < len(self.devices):
            return self.devices[index]
        
        return None
    
    def get_all_devices(self):
        """
        Tüm cihazların listesini döndürür
        
        Returns:
            list: Cihazların listesi
        """
        return self.devices


class NetworkScanner(QThread):
    """Ağ tarama işlemlerini arka planda gerçekleştiren iş parçacığı"""

    # Sinyal tanımlamaları
    device_found = pyqtSignal(str, str) # IP ve MAC adresi sinyali
    progress_updated = pyqtSignal(int) # İlerleme sinyali
    finished = pyqtSignal() # Tarama bitti sinyali

    def __init__(self, ip_range):
        """
        NetworkScanner sınıfı için yapıcı

        Args:
            ip_range (str): Taranacak IP aralığı (örn: 192.168.1.1-192.168.1.254)
        """
        super().__init__()
        self.ip_range = ip_range
        self._is_running = True # _is_running özniteliği eklendi

    def run(self):
        """İş parçacığının çalıştırma metodu"""
        try:
            start_ip, end_ip = self.ip_range.split('-')
            start_parts = list(map(int, start_ip.split('.')))
            end_parts = list(map(int, end_ip.split('.')))

            # IP aralığını kontrol et (basit kontrol)
            if len(start_parts) != 4 or len(end_parts) != 4:
                print("Geçersiz IP aralığı formatı")
                return

            # IP adreslerini tamsayıya çevirerek döngü oluştur
            start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]

            total_ips = end_int - start_int + 1
            for i, ip_int in enumerate(range(start_int, end_int + 1)):
                if not self._is_running:
                    break # İptal edildiyse döngüyü sonlandır

                # Tamsayı IP'yi stringe çevir
                ip_address = f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"

                # Ping komutu ile cihazın aktif olup olmadığını kontrol et
                # Windows için: ping -n 1 -w 1000 <ip_address> # Timeout 1 saniyeye çıkarıldı
                # Linux/macOS için: ping -c 1 -W 1 <ip_address>
                if sys.platform.startswith('win'):
                    command = ['ping', '-n', '1', '-w', '1000', ip_address] # Timeout 1 saniyeye çıkarıldı
                else:
                    command = ['ping', '-c', '1', '-W', '1', ip_address]

                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=1) # Timeout 1 saniyeye çıkarıldı
                    if result.returncode == 0:
                        # Cihaz aktif, MAC adresini bulmaya çalış
                        mac_address = self.get_mac_address(ip_address)
                        if mac_address:
                            self.device_found.emit(ip_address, mac_address)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass # Ping zaman aşımına uğradı veya komut bulunamadı
                except Exception as e:
                    print(f"Ping veya ARP hatası: {e}")

                # İlerleme çubuğunu güncelle
                self.progress_updated.emit(int((i + 1) / total_ips * 100))

        finally:
            self.finished.emit() # Döngü bittiğinde veya hata oluştuğunda sinyal yay

    def _parse_mac_from_arp(self, arp_output):
        """ARP çıktısından MAC adresini ayrıştırır"""
        # Windows formatı (xx-xx-xx-xx-xx-xx) veya Linux/macOS formatı (xx:xx:xx:xx:xx:xx)
        match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_output)
        if match:
            return match.group(0).replace('-', ':')
        return None

    def get_mac_address(self, ip_address):
        """ARP tablosundan MAC adresini almaya çalışır"""
        try:
            if sys.platform.startswith('win'):
                # Windows için arp -a komutu
                command = ['arp', '-a', ip_address]
            else:
                # Linux/macOS için arp <ip_address> komutu
                command = ['arp', ip_address]

            result = subprocess.run(command, capture_output=True, text=True, timeout=0.5)
            if result.returncode == 0:
                return self._parse_mac_from_arp(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass # Ping zaman aşımına uğradı veya komut bulunamadı
        except Exception as e: # Diğer hatalar için genel yakalama ve loglama (isteğe bağlı)
            print(f"MAC adresi alınırken hata oluştu: {e}")

        return None


class DeviceStatusChecker(QThread):
    """Cihazların çevrimiçi durumunu kontrol eden iş parçacığı"""

    # Sinyal tanımlamaları
    status_checked = pyqtSignal(str, bool) # IP adresi ve durum (True: çevrimiçi, False: çevrimdışı)
    finished = pyqtSignal() # Kontrol bitti sinyali

    def __init__(self, devices):
        """
        DeviceStatusChecker sınıfı için yapıcı

        Args:
            devices (list): Kontrol edilecek cihazların listesi (dict formatında)
        """
        super().__init__()
        self.devices = devices
        self._is_running = True

    def run(self):
        """İş parçacığının çalıştırma metodu"""
        for device in self.devices:
            if not self._is_running:
                break # İptal edildiyse döngüyü sonlandır

            ip_address = device.get('ip_address')
            if ip_address:
                is_online = self.check_ping(ip_address)
                self.status_checked.emit(ip_address, is_online)

        self.finished.emit()

    def check_ping(self, ip_address):
        """Belirtilen IP adresine ping atarak cihazın çevrimiçi olup olmadığını kontrol eder"""
        try:
            # Ping komutu
            if sys.platform.startswith('win'):
                command = ['C:\\Windows\\System32\\ping.exe', '-n', '1', '-w', '1000', ip_address] # Windows: Tam yolu belirtildi
            else:
                command = ['ping', '-c', '1', '-W', '2', ip_address] # Linux/macOS: -c 1 paket, -W 2s timeout

            result = subprocess.run(command, capture_output=True, text=True, timeout=2, creationflags=subprocess.CREATE_NO_WINDOW) # Zaman aşımı 2 saniyeye çıkarıldı ve pencere gizlendi
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False # Ping zaman aşımına uğradı veya komut bulunamadı
        except Exception as e: # Diğer hatalar için genel yakalama ve loglama (isteğe bağlı)
            print(f"Ping veya ARP hatası: {e}")

        return None

    def stop(self):
        """İş parçacığını durdurma isteği gönderir"""
        self._is_running = False


class WakeOnLANWorker(QThread):
    """Arka planda WOL işlemlerini gerçekleştiren iş parçacığı"""

    # Sinyal tanımlamaları
    finished = pyqtSignal(bool, str)

    def __init__(self, mac_address, broadcast_ip='255.255.255.255', port=9):
        """
        WakeOnLANWorker sınıfı için yapıcı

        Args:
            mac_address (str): Hedef cihazın MAC adresi
            broadcast_ip (str): Yayın IP adresi
            port (int): WOL portu
        """
        super().__init__()
        self.mac_address = mac_address
        self.broadcast_ip = broadcast_ip
        self.port = port

    def run(self):
        """İş parçacığının çalıştırma metodu"""
        result = WakeOnLAN.send_magic_packet(
            self.mac_address, self.broadcast_ip, self.port
        )

        if result:
            self.finished.emit(True, f"{self.mac_address} adresine WOL paketi gönderildi.")
        else:
            self.finished.emit(False, f"{self.mac_address} adresine WOL paketi gönderilemedi.")


class DeviceDialog(QDialog):
    """Cihaz ekleme/düzenleme için iletişim kutusu"""
    
    def __init__(self, parent=None, device=None):
        """
        DeviceDialog sınıfı için yapıcı
        
        Args:
            parent (QWidget, optional): Ebeveyn widget
            device (dict, optional): Düzenlenecek cihaz bilgileri
        """
        super().__init__(parent)
        
        self.setWindowTitle("Cihaz Ekle" if device is None else "Cihazı Düzenle")
        self.setMinimumWidth(400)
        
        # Form düzeni oluştur
        layout = QFormLayout(self)
        
        # Form alanlarını ekle
        self.name_edit = QLineEdit(self)
        self.mac_edit = QLineEdit(self)
        self.mac_edit.setPlaceholderText("00:11:22:33:44:55")
        self.ip_edit = QLineEdit(self)
        self.ip_edit.setPlaceholderText("192.168.1.100 (İsteğe bağlı)")
        layout.addRow("Cihaz Adı:", self.name_edit)
        layout.addRow("MAC Adresi:", self.mac_edit)
        layout.addRow("IP Adresi:", self.ip_edit)

        # Broadcast IP Alanı
        self.broadcast_ip_edit = QLineEdit(self)
        self.broadcast_ip_edit.setPlaceholderText("255.255.255.255 (Varsayılan)")
        layout.addRow("Broadcast IP:", self.broadcast_ip_edit)

        # İşletim Sistemi Seçimi
        self.os_combo = QComboBox(self)
        self.os_combo.addItems(["Bilinmiyor", "Windows", "Linux"])
        self.os_combo.setCurrentText("Windows") # Varsayılan olarak Windows seçili gelsin
        layout.addRow("İşletim Sistemi:", self.os_combo)

        # SSH Bilgileri
        self.ssh_user_edit = QLineEdit(self)
        self.ssh_password_edit = QLineEdit(self)
        self.ssh_password_edit.setEchoMode(QLineEdit.Password) # Şifreyi gizle
        self.ssh_key_edit = QLineEdit(self)
        self.ssh_key_edit.setPlaceholderText("Anahtar dosya yolu (isteğe bağlı)")
        
        layout.addRow("SSH Kullanıcı Adı:", self.ssh_user_edit)
        layout.addRow("SSH Şifresi:", self.ssh_password_edit)
        layout.addRow("SSH Anahtar Dosyası:", self.ssh_key_edit)
        
        # Düğmeler için butonlar oluştur
        save_button = QPushButton("Kaydet")
        cancel_button = QPushButton("İptal")

        # Butonları açıkça etkinleştir
        save_button.setEnabled(True)
        cancel_button.setEnabled(True)

        # Buton sinyallerini bağla
        # Buton sinyallerini bağla
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)

        # Butonları düzenlemeye ekle
        button_box = QDialogButtonBox()
        button_box.addButton(save_button, QDialogButtonBox.AcceptRole)
        button_box.addButton(cancel_button, QDialogButtonBox.RejectRole)
        
        layout.addWidget(button_box)
        
        # Eğer cihaz bilgisi varsa alanları doldur
        if device:
            self.name_edit.setText(device.get('name', ''))
            self.mac_edit.setText(device.get('mac_address', ''))
            self.ip_edit.setText(device.get('ip_address', ''))
            self.broadcast_ip_edit.setText(device.get('broadcast_ip', ''))
            self.os_combo.setCurrentText(device.get('os', 'Bilinmiyor'))
            self.ssh_user_edit.setText(device.get('ssh_user', ''))
            self.ssh_password_edit.setText(device.get('ssh_password', ''))
            self.ssh_key_edit.setText(device.get('ssh_key', ''))

    def get_data(self):
        """İletişim kutusundaki verileri döndürür"""
        return {
            'name': self.name_edit.text(),
            'mac_address': self.mac_edit.text(),
            'ip_address': self.ip_edit.text(),
            'broadcast_ip': self.broadcast_ip_edit.text(),
            'os': self.os_combo.currentText(),
            'ssh_user': self.ssh_user_edit.text(),
            'ssh_password': self.ssh_password_edit.text(),
            'ssh_key': self.ssh_key_edit.text(),
        }


class MainWindow(QMainWindow):
    """Ana uygulama penceresi"""

    def change_language(self, selection):
        """Dil değiştirme işlemini yapar"""
        if selection == 'Turkish':
            self.current_lang = 'tr'
        else:
            self.current_lang = 'en'
        self.init_ui() # Arayüzü yeniden çiz
        self.load_devices() # Cihazları yeniden yükle ve tabloyu doldur

    def __init__(self):
        """MainWindow sınıfı için yapıcı"""
        super().__init__()

        # Cihaz yöneticisini başlat
        self.device_manager = DeviceManager()

        # Dil özniteliğini tanımla
        self.current_lang = "en" # Başlangıç dili

        # Ağ tarayıcı ve durum denetleyicisi iş parçacıkları
        self.scanner_thread = None
        self.status_checker_thread = None

        # Kullanıcı arayüzünü başlat
        self.init_ui()

        # Kayıtlı cihazları yükle ve tabloyu doldur
        self.load_devices()

        # Pencere başlığını ayarla
        self.setWindowTitle("Wake On LAN")
        self.setGeometry(100, 100, 800, 600) # Pencere boyutunu ayarla
        self.setWindowIcon(QIcon("./lan.ico")) # Uygulama ikonunu ayarla

        # Add current device index tracker
        self.selected_device_row = None

    def select_device_by_row(self, row):
        """Belirtilen satırdaki cihazı seçer ve kontrol butonlarını görünür yapar"""
        if row is not None and 0 <= row < self.device_table.rowCount():
            self.selected_device_row = row
            self.device_controls.setVisible(True)
            device = self.device_table.item(row, 0).data(Qt.UserRole)
            self.selected_device_label.setText(f"{translations['selected_device_label'][self.current_lang]}: {device.get('name', 'Bilinmiyor')}")
        else:
            self.selected_device_row = None
            self.device_controls.setVisible(False)
            self.selected_device_label.setText(translations["selected_device_label"][self.current_lang])


    def init_ui(self):
        """Kullanıcı arayüzünü başlatır"""
        # Ana widget oluştur
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Sol sidebar
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 30, 20, 20)
        sidebar_layout.setSpacing(15)
        
        # Uygulama başlığı
        title_label = QLabel("Wake On LAN")
        title_label.setObjectName("appTitle")
        sidebar_layout.addWidget(title_label)
        
        # Ayraç
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("separator")
        sidebar_layout.addWidget(line)
        
        # Ana işlem butonları
        add_button = QPushButton(translations["add_button"][self.current_lang])
        add_button.setMinimumHeight(40)
        add_button.setObjectName("primaryButton")
        add_button.clicked.connect(self.add_device)
        sidebar_layout.addWidget(add_button)
        
        scan_button = QPushButton(translations["scan_button"][self.current_lang])
        scan_button.setMinimumHeight(40)
        scan_button.setObjectName("secondaryButton")
        scan_button.clicked.connect(self.start_scan)
        sidebar_layout.addWidget(scan_button)

        # Durum Yenile Butonu
        refresh_button = QPushButton(translations["refresh_button"][self.current_lang])
        refresh_button.setMinimumHeight(40)
        refresh_button.setObjectName("secondaryButton")
        refresh_button.clicked.connect(self.start_status_check)
        sidebar_layout.addWidget(refresh_button)

        # Language selector
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(['Turkish', 'English'])
        self.lang_combo.setCurrentText('English' if self.current_lang == 'en' else 'Turkish')
        self.lang_combo.currentTextChanged.connect(self.change_language)
        self.lang_combo.setMinimumHeight(40)
        self.lang_combo.setObjectName("languageSelector")
        sidebar_layout.addWidget(self.lang_combo)
        
        # Seçili cihaz kontrolleri (başlangıçta gizli)
        self.device_controls = QWidget()
        self.device_controls.setVisible(False)
        device_controls_layout = QVBoxLayout(self.device_controls)
        
        # Seçili cihaz başlığı
        self.selected_device_label = QPushButton(translations["selected_device_label"][self.current_lang])
        self.selected_device_label.setObjectName("sectionTitle")
        device_controls_layout.addWidget(self.selected_device_label)
        
        # Ayraç
        device_line = QFrame()
        device_line.setFrameShape(QFrame.HLine)
        device_line.setObjectName("separator")
        device_controls_layout.addWidget(device_line)
        
        # Cihaz kontrol butonları
        self.wake_button = QPushButton(translations["wake_button"][self.current_lang])
        self.wake_button.setObjectName("actionButton")
        self.wake_button.clicked.connect(self.wake_device)
        device_controls_layout.addWidget(self.wake_button)
        
        self.shutdown_button = QPushButton(translations["shutdown_button"][self.current_lang])
        self.shutdown_button.setObjectName("actionButton")
        self.shutdown_button.clicked.connect(lambda: self.shutdown_device(None))
        device_controls_layout.addWidget(self.shutdown_button)
        
        self.restart_button = QPushButton(translations["restart_button"][self.current_lang])
        self.restart_button.setObjectName("actionButton")
        self.restart_button.clicked.connect(lambda: self.restart_device(None))
        device_controls_layout.addWidget(self.restart_button)
        
        self.edit_button = QPushButton(translations["edit_button"][self.current_lang])
        self.edit_button.setObjectName("actionButton")
        self.edit_button.clicked.connect(self.edit_device)
        device_controls_layout.addWidget(self.edit_button)
        
        self.delete_button = QPushButton(translations["delete_button"][self.current_lang])
        self.delete_button.setObjectName("actionButton")
        self.delete_button.clicked.connect(self.delete_device)
        device_controls_layout.addWidget(self.delete_button)
        
        sidebar_layout.addWidget(self.device_controls)
        sidebar_layout.addStretch()
        main_layout.addWidget(sidebar)
        
        # Add current device index tracker
        self.selected_device_row = None

        # Sağ içerik alanı
        content_widget = QWidget()
        content_widget.setObjectName("contentArea")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(30, 30, 30, 30)
        content_layout.setSpacing(20)
        
        # Başlık alanı
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        header_label = QPushButton(translations["header_label"][self.current_lang])
        header_label.setObjectName("contentTitle")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        content_layout.addWidget(header_widget)
        
        # Cihaz tablosu
        self.device_table = QTableWidget()
        self.device_table.setObjectName("deviceTable")

        # Add cell click handler
        self.device_table.cellClicked.connect(self.handle_cell_click)
        
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.setShowGrid(False)
        self.device_table.setAlternatingRowColors(True)
        
        # Enable horizontal scrolling if needed
        self.device_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        content_layout.addWidget(self.device_table)
        
        main_layout.addWidget(content_widget)

      

        # Modern stil tanımlamaları
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ffffff;
            }
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 10pt;
            }
            #sidebar {
                background-color: #1a1a1a;
                border-right: 1px solid #2d2d2d;
            }
            #sectionTitle {
                color: #ffffff;
                font-size: 16px;
                font-weight: 600;
                margin-bottom: 8px;
            }
            #actionButton {
                background-color: #2d2d2d;
                color: white;
                margin-bottom: 6px;
                text-align: left;
                padding: 14px; /* Adjusted padding: 8px top/bottom, 15px left/right */
            }
            #actionButton:hover {
                background-color: #3d3d3d;
            }
            #actionButton:disabled {
                background-color: #1a1a1a;
                color: #666666;
            }
            #appTitle {
                color: #ffffff;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
            }
            #separator {
                background-color: #2d2d2d;
                height: 1px;
                margin: 10px 0;
            }
            #primaryButton, #secondaryButton {
                border: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 11pt;
                text-align: left;
                padding: 10px 15px;
            }
            #primaryButton {
                background-color: #2196f3;
                color: white;
            }
            #primaryButton:hover {
                background-color: #1976d2;
            }
            #secondaryButton {
                background-color: #2d2d2d;
                color: white;
            }
            #secondaryButton:hover {
                background-color: #3d3d3d;
            }
            #contentArea {
                background-color: #f5f5f5;
            }
            #contentTitle {
                font-size: 20px;
                font-weight: 600;
                color: #1a1a1a;
            }
            #deviceTable {
                background-color: white;
                border: none;
                border-radius: 10px;
            }
            QTableWidget {
                gridline-color: #f0f0f0;
                selection-background-color: #e3f2fd;
                selection-color: #1a1a1a;
            }
            QTableWidget::item {
                padding: 4px 8px;
                border-bottom: 1px solid #f0f0f0;
                font-size: 9.5pt;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
            }
            QHeaderView::section {
                background-color: white;
                padding: 8px;
                border: none;
                border-bottom: 2px solid #f0f0f0;
                font-weight: bold;
                color: #1a1a1a;
                font-size: 9.5pt;
            }
            QPushButton {
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 500;
                color: white;
            }
            QPushButton[class="success"] {
                background-color: #4caf50;
            }
            QPushButton[class="success"]:hover {
                background-color: #388e3c;
            }
            QPushButton[class="warning"] {
                background-color: #ff9800;
            }
            QPushButton[class="warning"]:hover {
                background-color: #f57c00;
            }
            QPushButton[class="danger"] {
                background-color: #f44336;
            }
            QPushButton[class="danger"]:hover {
                background-color: #d32f2f;
            }
            QPushButton[class="info"] {
                background-color: #2196f3;
            }
            QPushButton[class="info"]:hover {
                background-color: #1976d2;
            }
            QLineEdit, QComboBox {
                padding: 10px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                background-color: white;
                color: #1a1a1a; /* Add this line */
            }
            #languageSelector {
                background-color: #2d2d2d;
                color: white;
                border: none;
                text-align: left;
                padding: 10px 15px;
                margin-top: 10px;
            }
            #languageSelector:hover {
                background-color: #3d3d3d;
            }
            QComboBox::item { /* Style for items in the dropdown list */
                color: #1a1a1a; /* Black text for items */
            }
            QComboBox::item:selected {
                background-color: #e3f2fd; /* Keep the selected background */
                color: #1a1a1a; /* Ensure selected text is black */
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #2196f3;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
            }
            QScrollBar:vertical {
                border: none;
                background: #f5f5f5;
                width: 10px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #bdbdbd;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
            }
            QMessageBox QPushButton { /* Style for buttons inside QMessageBox */
                color: black;
                border: 1px solid black;
                background-color: white; /* Optional: Set a background */
                padding: 5px 15px;
                min-width: 60px; /* Ensure buttons have some width */
            }
            QMessageBox QPushButton:hover {
                background-color: #f0f0f0; /* Optional: Hover effect */
            }
""")
        # Sistem tepsisi ikonu oluştur
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("./lan.ico")) # İkon dosyası atanıyor
        self.tray_icon.setToolTip("Wake On LAN Uygulaması") # İkon üzerine gelince görünecek yazı

        # Sistem tepsisi menüsü oluştur (isteğe bağlı)
        tray_menu = QMenu()
        exit_action = tray_menu.addAction("Çıkış")
        exit_action.triggered.connect(QApplication.instance().quit)

        self.tray_icon.setContextMenu(tray_menu)

        # Sistem tepsisi ikonunu göster
        self.tray_icon.show()

    def populate_device_table(self):
        """Cihaz listesini tablodan alıp tabloyu doldurur"""
        self.device_table.setRowCount(0) # Tabloyu temizle
        self.device_table.setColumnCount(4)
        self.device_table.setHorizontalHeaderLabels(["Ad", "MAC Adresi", "IP Adresi", "Durum"])

        # Optimize column widths
        header = self.device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Device Name
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # MAC Address
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # IP Address
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Status

        devices = self.device_manager.get_all_devices()
        for row, device in enumerate(devices):
            self._add_device_to_table(row, device)

    def _add_device_to_table(self, row, device, is_scanned=False):
        """Tabloya tek bir cihaz ekler"""
        self.device_table.insertRow(row)

        name_item = QTableWidgetItem(device.get('name', 'Bilinmiyor'))
        mac_item = QTableWidgetItem(device.get('mac_address', 'Bilinmiyor'))
        ip_item = QTableWidgetItem(device.get('ip_address', 'Bilinmiyor'))
        status_item = QTableWidgetItem(translations["status_offline"][self.current_lang]) # Başlangıçta çevrimdışı

        self.device_table.setItem(row, 0, name_item)
        self.device_table.setItem(row, 1, mac_item)
        self.device_table.setItem(row, 2, ip_item)
        self.device_table.setItem(row, 3, status_item)

        # Düzenleme ve silme işlemlerini kolaylaştırmak için cihaz verisini öğeye sakla
        self.device_table.item(row, 0).setData(Qt.UserRole, device)

        # Taranan cihazlar için farklı renk (isteğe bağlı)
        if is_scanned:
            for col in range(self.device_table.columnCount()):
                self.device_table.item(row, col).setBackground(QColor(230, 245, 255)) # Açık mavi
        self.start_status_check()


    def load_devices(self):
        """Kayıtlı cihazları yükler ve tabloyu doldurur"""
        self.device_manager = DeviceManager()
        self.populate_device_table() # Cihazları yükledikten sonra tabloyu doldur
        self.start_status_check() # Cihaz durumu kontrolünü başlat


    def start_scan(self):
        """Ağ taramasını başlatır"""
        # Tarama zaten çalışıyorsa tekrar başlatma
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.information(self, "Tarama Devam Ediyor", "Ağ taraması zaten devam ediyor.")
            return

        # IP aralığı alma iletişim kutusu
        ip_dialog = QDialog(self)
        ip_dialog.setWindowTitle("IP Aralığı Girin")
        layout = QFormLayout(ip_dialog)

        ip_range_edit = QLineEdit(ip_dialog)
        ip_range_edit.setPlaceholderText("örn: 192.168.1.1-192.168.1.254")
        layout.addRow("IP Aralığı:", ip_range_edit)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, ip_dialog)
        button_box.accepted.connect(ip_dialog.accept)
        button_box.rejected.connect(ip_dialog.reject)
        layout.addWidget(button_box)

        if ip_dialog.exec_() == QDialog.Accepted:
            ip_range = ip_range_edit.text()
            if not ip_range:
                QMessageBox.warning(self, "Geçersiz Giriş", "Lütfen bir IP aralığı girin.")
                return

            # Tarama iş parçacığını başlat
            self.scanner_thread = NetworkScanner(ip_range)
            self.scanner_thread.device_found.connect(self.add_scanned_device_to_table)
            self.scanner_thread.progress_updated.connect(self.update_scan_progress)
            self.scanner_thread.finished.connect(self.scan_finished)

            # İlerleme çubuğu oluştur
            total_ips = self.get_ip_count(ip_range)
            self.progress_dialog = QProgressDialog("Ağ Taranıyor...", "İptal", 0, 100, self)
            self.progress_dialog.setWindowTitle("Tarama Devam Ediyor")
            self.progress_dialog.setWindowModality(Qt.WindowModal)
            self.progress_dialog.canceled.connect(self.cancel_scan)
            self.progress_dialog.show()

            self.scanner_thread.start()

    def get_ip_count(self, ip_range):
        """IP aralığındaki toplam IP sayısını hesaplar"""
        try:
            start_ip, end_ip = ip_range.split('-')
            start_parts = list(map(int, start_ip.split('.')))
            end_parts = list(map(int, end_ip.split('.')))

            if len(start_parts) != 4 or len(end_parts) != 4:
                return 0

            start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]

            return end_int - start_int + 1
        except Exception:
            return 0

    def start_status_check(self):
        """Tüm cihazların çevrimiçi durumunu kontrol etmeyi başlatır"""
        # Önceki kontrol çalışıyorsa durdur
        if self.status_checker_thread and self.status_checker_thread.isRunning():
            self.status_checker_thread.stop()
            self.status_checker_thread.wait() # İş parçacığının bitmesini bekle

        devices = self.device_manager.get_all_devices()
        if not devices:
            return # Kontrol edilecek cihaz yok

        self.status_checker_thread = DeviceStatusChecker(devices)
        self.status_checker_thread.status_checked.connect(self.update_device_status)
        self.status_checker_thread.finished.connect(self.status_check_finished)
        self.status_checker_thread.start()

    def start_status_check_for_device(self, row):
        """Belirtilen satırdaki cihazın çevrimiçi durumunu kontrol etmeyi başlatır"""
        if 0 <= row < self.device_table.rowCount():
            device_item = self.device_table.item(row, 0)
            if device_item:
                device = device_item.data(Qt.UserRole)
                if device and device.get('ip_address'):
                     # Önceki kontrol çalışıyorsa durdur
                    if self.status_checker_thread and self.status_checker_thread.isRunning():
                        self.status_checker_thread.stop()
                        self.status_checker_thread.wait() # İş parçacığının bitmesini bekle

                    self.status_checker_thread = DeviceStatusChecker([device]) # Sadece seçili cihazı kontrol et
                    self.status_checker_thread.status_checked.connect(self.update_device_status)
                    self.status_checker_thread.finished.connect(self.status_check_finished)
                    self.status_checker_thread.start()


    def update_device_status(self, ip_address, is_online):
        """Tablodaki cihazın durumunu günceller"""
        for row in range(self.device_table.rowCount()):
            ip_item = self.device_table.item(row, 2) # IP adresi sütunu
            if ip_item and ip_item.text() == ip_address:
                status_item = self.device_table.item(row, 3) # Durum sütunu
                if status_item:
                    if is_online:
                        status_item.setText(translations["status_online"][self.current_lang])
                        status_item.setForeground(QColor("green"))
                    else:
                        status_item.setText(translations["status_offline"][self.current_lang])
                        status_item.setForeground(QColor("red"))
                break # Cihaz bulundu, döngüyü sonlandır

    def update_scan_progress(self, value):
        """Tarama ilerleme çubuğunu günceller"""
        if self.progress_dialog:
            self.progress_dialog.setValue(value)

    def status_check_finished(self):
        """Durum kontrolü bittiğinde çağrılır"""
        print("Durum kontrolü tamamlandı.") # İsteğe bağlı: Konsola bilgi yazdır

    def add_scanned_device_to_table(self, ip_address, mac_address):
        """Taranan cihazı tabloya ekler (eğer listede yoksa)"""
        # Cihazın listede olup olmadığını kontrol et
        for row in range(self.device_table.rowCount()):
            mac_item = self.device_table.item(row, 1)
            if mac_item and mac_item.text().lower() == mac_address.lower():
                # Cihaz zaten listede, IP adresini güncelle (eğer boşsa)
                ip_item = self.device_table.item(row, 2)
                if ip_item and not ip_item.text():
                    ip_item.setText(ip_address)
                    # Cihaz yöneticisindeki bilgiyi de güncelle
                    device = self.device_table.item(row, 0).data(Qt.UserRole)
                    if device:
                        device['ip_address'] = ip_address
                        # Cihaz yöneticisindeki cihazı bulup güncelle
                        for i, dev in enumerate(self.device_manager.devices):
                            if dev['mac_address'].lower() == mac_address.lower():
                                self.device_manager.devices[i]['ip_address'] = ip_address
                                self.device_manager._save_devices()
                                break
                return # Cihaz bulundu, eklemeye gerek yok

        # Cihaz listede yok, yeni olarak ekle
        row = self.device_table.rowCount()
        device = {
            'name': f"Yeni Cihaz ({ip_address})",
            'mac_address': mac_address,
            'ip_address': ip_address,
            'broadcast_ip': '', # Tarama ile broadcast IP gelmez
            'os': 'Bilinmiyor', # Tarama ile OS bilgisi gelmez
            'ssh_user': '',
            'ssh_password': '',
            'ssh_key': '',
        }
        self.device_manager.add_device(
            device['name'], device['mac_address'], device['ip_address'],
            device['broadcast_ip'], device['os'], device['ssh_user'],
            device['ssh_password'], device['ssh_key']
        )
        self.populate_device_table() # Tabloyu yeniden doldur

    def scan_finished(self):
        """Tarama bittiğinde çağrılır"""
        if self.progress_dialog:
            self.progress_dialog.close()
        QMessageBox.information(self, "Tarama Tamamlandı", "Ağ taraması tamamlandı.")
        self.start_status_check() # Tarama bitince cihaz durumlarını kontrol et

    def handle_cell_click(self, row, column):
        """Tablo hücresine tıklandığında ilgili cihazı seçer"""
        self.select_device_by_row(row)

    def show_context_menu(self, pos):
        """Tabloya sağ tıklandığında bağlam menüsünü gösterir"""
        # Tıklanan hücrenin satırını al
        item = self.device_table.itemAt(pos)
        if item:
            row = item.row()
            self.select_device_by_row(row) # Cihazı seç

            # Bağlam menüsü oluştur
            context_menu = QMenu(self)
            wake_action = context_menu.addAction(translations["wake_button"][self.current_lang])
            shutdown_action = context_menu.addAction(translations["shutdown_button"][self.current_lang])
            restart_action = context_menu.addAction(translations["restart_button"][self.current_lang])
            edit_action = context_menu.addAction(translations["edit_button"][self.current_lang])
            delete_action = context_menu.addAction(translations["delete_button"][self.current_lang])
            refresh_status_action = context_menu.addAction(translations["refresh_button"][self.current_lang] + " (Durum)")


            # Eylemleri bağla
            wake_action.triggered.connect(self.wake_device)
            shutdown_action.triggered.connect(lambda: self.shutdown_device(None)) # None, seçili cihazı kullanacak
            restart_action.triggered.connect(lambda: self.restart_device(None)) # None, seçili cihazı kullanacak
            edit_action.triggered.connect(self.edit_device)
            delete_action.triggered.connect(self.delete_device)
            refresh_status_action.triggered.connect(lambda: self.start_status_check_for_device(row))


            # Menüyü göster
            context_menu.exec_(self.device_table.mapToGlobal(pos))

    def add_selected_scanned_device(self, row):
        """Taranan cihazlar listesinden seçilen cihazı ana listeye ekler"""
        # Bu metod artık kullanılmıyor gibi görünüyor, kaldırılabilir veya güncellenebilir.
        # Eğer taranan cihazlar ayrı bir tabloda gösteriliyorsa bu metodun güncellenmesi gerekir.
        pass # Şimdilik boş bırakıldı

    def cancel_scan(self):
        """Ağ taramasını iptal eder"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread._is_running = False # İş parçacığına durma sinyali gönder
            self.scanner_thread.wait() # İş parçacığının bitmesini bekle
            QMessageBox.information(self, "Tarama İptal Edildi", "Ağ taraması kullanıcı tarafından iptal edildi.")


    def _validate_device_data(self, data):
        """Cihaz verilerini doğrular"""
        if not data.get('name'):
            QMessageBox.warning(self, "Eksik Bilgi", "Cihaz adı boş olamaz.")
            return False
        if not data.get('mac_address'):
            QMessageBox.warning(self, "Eksik Bilgi", "MAC adresi boş olamaz.")
            return False
        if not WakeOnLAN.validate_mac_address(data.get('mac_address', '')):
            QMessageBox.warning(self, "Geçersiz MAC Adresi", "Lütfen geçerli bir MAC adresi girin.")
            return False
        return True

    def add_device(self):
        """Yeni cihaz ekleme iletişim kutusunu gösterir"""
        dialog = DeviceDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            if self._validate_device_data(data):
                if self.device_manager.add_device(
                    data['name'], data['mac_address'], data['ip_address'],
                    data['broadcast_ip'], data['os'], data['ssh_user'],
                    data['ssh_password'], data['ssh_key']
                ):
                    QMessageBox.information(self, "Başarılı", "Cihaz başarıyla eklendi.")
                    self.populate_device_table() # Tabloyu güncelle
                else:
                    QMessageBox.warning(self, "Hata", "Cihaz eklenirken bir hata oluştu veya MAC adresi zaten mevcut.")

    def edit_device(self):
        """Seçili cihazı düzenleme iletişim kutusunu gösterir"""
        if self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                dialog = DeviceDialog(self, device)
                if dialog.exec_() == QDialog.Accepted:
                    data = dialog.get_data()
                    if self._validate_device_data(data):
                        if self.device_manager.update_device(
                            self.selected_device_row, data['name'], data['mac_address'],
                            data['ip_address'], data['broadcast_ip'], data['os'],
                            data['ssh_user'], data['ssh_password'], data['ssh_key']
                        ):
                            QMessageBox.information(self, "Başarılı", "Cihaz başarıyla güncellendi.")
                            self.populate_device_table() # Tabloyu güncelle
                        else:
                            QMessageBox.warning(self, "Hata", "Cihaz güncellenirken bir hata oluştu veya MAC adresi zaten mevcut.")
        else:
            QMessageBox.warning(self, "Uyarı", "Lütfen düzenlemek için bir cihaz seçin.")

    def delete_device(self):
        """Seçili cihazı siler"""
        if self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                reply = QMessageBox.question(
                    self, "Cihazı Sil",
                    f"{device.get('name', 'Bilinmiyor')} adlı cihazı silmek istediğinizden emin misiniz?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    if self.device_manager.remove_device(self.selected_device_row):
                        QMessageBox.information(self, "Başarılı", "Cihaz başarıyla silindi.")
                        self.populate_device_table() # Tabloyu güncelle
                        self.select_device_by_row(None) # Seçimi kaldır
                    else:
                        QMessageBox.warning(self, "Hata", "Cihaz silinirken bir hata oluştu.")
        else:
            QMessageBox.warning(self, "Uyarı", "Lütfen silmek için bir cihaz seçin.")

    def shutdown_device(self, ip_address):
        """Belirtilen IP adresine sahip cihazı kapatır (SSH üzerinden)"""
        target_ip = ip_address
        if target_ip is None and self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                target_ip = device.get('ip_address')
                ssh_user = device.get('ssh_user')
                ssh_password = device.get('ssh_password')
                ssh_key = device.get('ssh_key')
            else:
                QMessageBox.warning(self, "Hata", "Seçili cihaz bilgileri alınamadı.")
                return

        if not target_ip:
            QMessageBox.warning(self, "Hata", "Kapatılacak cihazın IP adresi belirtilmemiş.")
            return

        if not ssh_user:
             QMessageBox.warning(self, "Hata", "SSH kullanıcı adı belirtilmemiş.")
             return

        # SSH ile kapatma komutunu gönder
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if ssh_password:
                client.connect(target_ip, username=ssh_user, password=ssh_password, timeout=5)
            elif ssh_key and os.path.exists(ssh_key):
                 client.connect(target_ip, username=ssh_user, key_filename=ssh_key, timeout=5)
            else:
                 QMessageBox.warning(self, "Hata", "SSH bağlantısı için şifre veya geçerli anahtar dosyası belirtilmemiş.")
                 return

            # İşletim sistemine göre kapatma komutu
            os_type = device.get('os', 'Bilinmiyor').lower()
            command = ""
            if os_type == 'windows':
                command = "shutdown /s /t 1" # Windows için kapatma komutu
            elif os_type == 'linux':
                command = "sudo shutdown now" # Linux için kapatma komutu
            else:
                QMessageBox.warning(self, "Hata", f"Desteklenmeyen işletim sistemi: {device.get('os', 'Bilinmiyor')}. Lütfen cihaz bilgilerini güncelleyin.")
                client.close()
                return

            stdin, stdout, stderr = client.exec_command(command)

            # Komut çıktısını oku
            stdout_output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()

            # print(stdout_output) # İsteğe bağlı loglama
            # print(stderr_output) # İsteğe bağlı loglama

            client.close()
            QMessageBox.information(self, "Başarılı", f"{target_ip} adresindeki cihaza kapatma komutu gönderildi.")
        except paramiko.AuthenticationException:
            QMessageBox.warning(self, "SSH Hatası", f"SSH kimlik doğrulama hatası. Kullanıcı adı veya şifre/anahtar yanlış.\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except paramiko.SSHException as e:
            QMessageBox.warning(self, "SSH Hatası", f"SSH bağlantı hatası: {e}\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except socket.timeout:
             QMessageBox.warning(self, "Bağlantı Hatası", f"{target_ip} adresine SSH bağlantısı zaman aşımına uğradı.\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Cihaz kapatılırken bir hata oluştu: {e}\nStdout: {stdout_output}\nStderr: {stderr_output}")


    def restart_device(self, ip_address):
        """Belirtilen IP adresine sahip cihazı yeniden başlatır (SSH üzerinden)"""
        target_ip = ip_address
        if target_ip is None and self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                target_ip = device.get('ip_address')
                ssh_user = device.get('ssh_user')
                ssh_password = device.get('ssh_password')
                ssh_key = device.get('ssh_key')
            else:
                QMessageBox.warning(self, "Hata", "Seçili cihaz bilgileri alınamadı.")
                return

        if not target_ip:
            QMessageBox.warning(self, "Hata", "Yeniden başlatılacak cihazın IP adresi belirtilmemiş.")
            return

        if not ssh_user:
             QMessageBox.warning(self, "Hata", "SSH kullanıcı adı belirtilmemiş.")
             return

        # SSH ile yeniden başlatma komutunu gönder
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if ssh_password:
                client.connect(target_ip, username=ssh_user, password=ssh_password, timeout=5)
            elif ssh_key and os.path.exists(ssh_key):
                 client.connect(target_ip, username=ssh_user, key_filename=ssh_key, timeout=5)
            else:
                 QMessageBox.warning(self, "Hata", "SSH bağlantısı için şifre veya geçerli anahtar dosyası belirtilmemiş.")
                 return

            # İşletim sistemine göre yeniden başlatma komutu
            # Basit bir tahmin: Windows için shutdown /r /t 1, Linux için sudo reboot
            stdin, stdout, stderr = client.exec_command("sudo reboot") # Linux için örnek
            # stdin, stdout, stderr = client.exec_command("shutdown /r /t 1") # Windows için örnek

            # Komut çıktısını oku
            stdout_output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()

            # print(stdout_output) # İsteğe bağlı loglama
            # print(stderr_output) # İsteğe bağlı loglama

            client.close()
            QMessageBox.information(self, "Başarılı", f"{target_ip} adresindeki cihaza yeniden başlatma komutu gönderildi.")
        except paramiko.AuthenticationException:
            QMessageBox.warning(self, "SSH Hatası", f"SSH kimlik doğrulama hatası. Kullanıcı adı veya şifre/anahtar yanlış.\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except paramiko.SSHException as e:
            QMessageBox.warning(self, "SSH Hatası", f"SSH bağlantı hatası: {e}\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except socket.timeout:
             QMessageBox.warning(self, "Bağlantı Hatası", f"{target_ip} adresine SSH bağlantısı zaman aşımına uğradı.\nStdout: {stdout_output}\nStderr: {stderr_output}")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Cihaz yeniden başlatılırken bir hata oluştu: {e}\nStdout: {stdout_output}\nStderr: {stderr_output}")


    def wake_device(self):
        """Seçili cihazı Wake On LAN ile uyandırır"""
        if self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                mac_address = device.get('mac_address')
                broadcast_ip = device.get('broadcast_ip', '255.255.255.255') # Varsayılan broadcast IP
                if mac_address:
                    # WOL işlemini arka planda yap
                    self.wol_worker = WakeOnLANWorker(mac_address, broadcast_ip)
                    self.wol_worker.finished.connect(self.on_wake_finished)
                    self.wol_worker.start()
                else:
                    QMessageBox.warning(self, "Hata", "Seçili cihazın MAC adresi belirtilmemiş.")
        else:
            QMessageBox.warning(self, "Uyarı", "Lütfen uyandırmak için bir cihaz seçin.")

    def on_wake_finished(self, success, message):
        """WOL işlemi bittiğinde çağrılır"""
        if success:
            QMessageBox.information(self, "WOL Başarılı", message)
        else:
            QMessageBox.warning(self, "WOL Hatası", message)

    def shutdown_device(self, ip_address):
        """Belirtilen IP adresine sahip cihazı kapatır (SSH üzerinden)"""
        target_ip = ip_address
        if target_ip is None and self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                target_ip = device.get('ip_address')
                ssh_user = device.get('ssh_user')
                ssh_password = device.get('ssh_password')
                ssh_key = device.get('ssh_key')
            else:
                QMessageBox.warning(self, "Hata", "Seçili cihaz bilgileri alınamadı.")
                return

        if not target_ip:
            QMessageBox.warning(self, "Hata", "Kapatılacak cihazın IP adresi belirtilmemiş.")
            return

        if not ssh_user:
             QMessageBox.warning(self, "Hata", "SSH kullanıcı adı belirtilmemiş.")
             return

        # SSH ile kapatma komutunu gönder
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if ssh_password:
                client.connect(target_ip, username=ssh_user, password=ssh_password, timeout=5)
            elif ssh_key and os.path.exists(ssh_key):
                 client.connect(target_ip, username=ssh_user, key_filename=ssh_key, timeout=5)
            else:
                 QMessageBox.warning(self, "Hata", "SSH bağlantısı için şifre veya geçerli anahtar dosyası belirtilmemiş.")
                 return

            # İşletim sistemine göre kapatma komutu
            # Basit bir tahmin: Windows için shutdown /s /t 1, Linux için sudo shutdown now
            # Daha gelişmiş bir uygulama için işletim sistemi bilgisi kullanılabilir.
            # stdin, stdout, stderr = client.exec_command("sudo shutdown now") # Linux için örnek
            stdin, stdout, stderr = client.exec_command("shutdown /s /t 1") # Windows için örnek
            # stdin, stdout, stderr = client.exec_command("shutdown /s /t 1") # Windows için örnek

            # Komut çıktısını oku (isteğe bağlı)
            # print(stdout.read().decode())
            # print(stderr.read().decode())

            client.close()
            QMessageBox.information(self, "Başarılı", f"{target_ip} adresindeki cihaza kapatma komutu gönderildi.")
        except paramiko.AuthenticationException:
            QMessageBox.warning(self, "SSH Hatası", "SSH kimlik doğrulama hatası. Kullanıcı adı veya şifre/anahtar yanlış.")
        except paramiko.SSHException as e:
            QMessageBox.warning(self, "SSH Hatası", f"SSH bağlantı hatası: {e}")
        except socket.timeout:
             QMessageBox.warning(self, "Bağlantı Hatası", f"{target_ip} adresine SSH bağlantısı zaman aşımına uğradı.")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Cihaz kapatılırken bir hata oluştu: {e}")


    def restart_device(self, ip_address):
        """Belirtilen IP adresine sahip cihazı yeniden başlatır (SSH üzerinden)"""
        target_ip = ip_address
        if target_ip is None and self.selected_device_row is not None:
            device = self.device_table.item(self.selected_device_row, 0).data(Qt.UserRole)
            if device:
                target_ip = device.get('ip_address')
                ssh_user = device.get('ssh_user')
                ssh_password = device.get('ssh_password')
                ssh_key = device.get('ssh_key')
            else:
                QMessageBox.warning(self, "Hata", "Seçili cihaz bilgileri alınamadı.")
                return

        if not target_ip:
            QMessageBox.warning(self, "Hata", "Yeniden başlatılacak cihazın IP adresi belirtilmemiş.")
            return

        if not ssh_user:
             QMessageBox.warning(self, "Hata", "SSH kullanıcı adı belirtilmemiş.")
             return

        # SSH ile yeniden başlatma komutunu gönder
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if ssh_password:
                client.connect(target_ip, username=ssh_user, password=ssh_password, timeout=5)
            elif ssh_key and os.path.exists(ssh_key):
                 client.connect(target_ip, username=ssh_user, key_filename=ssh_key, timeout=5)
            else:
                 QMessageBox.warning(self, "Hata", "SSH bağlantısı için şifre veya geçerli anahtar dosyası belirtilmemiş.")
                 return

            # İşletim sistemine göre yeniden başlatma komutu
            # Basit bir tahmin: Windows için shutdown /r /t 1, Linux için sudo reboot
            # stdin, stdout, stderr = client.exec_command("sudo reboot") # Linux için örnek
            stdin, stdout, stderr = client.exec_command("shutdown /r /t 1") # Windows için örnek
            # stdin, stdout, stderr = client.exec_command("shutdown /r /t 1") # Windows için örnek

            # Komut çıktısını oku (isteğe bağlı)
            # print(stdout.read().decode())
            # print(stderr.read().decode())

            client.close()
            QMessageBox.information(self, "Başarılı", f"{target_ip} adresindeki cihaza yeniden başlatma komutu gönderildi.")
        except paramiko.AuthenticationException:
            QMessageBox.warning(self, "SSH Hatası", "SSH kimlik doğrulama hatası. Kullanıcı adı veya şifre/anahtar yanlış.")
        except paramiko.SSHException as e:
            QMessageBox.warning(self, "SSH Hatası", f"SSH bağlantı hatası: {e}")
        except socket.timeout:
             QMessageBox.warning(self, "Bağlantı Hatası", f"{target_ip} adresine SSH bağlantısı zaman aşımına uğradı.")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Cihaz yeniden başlatılırken bir hata oluştu: {e}")


def main():
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion")) # Modern stil kullan
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
