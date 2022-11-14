import base64
from io import BytesIO
import sys
import base64
from PyQt5.QtWidgets import QLineEdit, QPushButton, QWidget, \
    QLabel, QApplication, QTextEdit, QMessageBox, QFileDialog, QProgressBar
from PyQt5.QtCore import QThread, pyqtSignal


from backend import *


class DesEncode(QThread):
    """
    DES encryption Thread
    """
    _signal = pyqtSignal(str)
    _progress_signal = pyqtSignal(float)
 
    def __init__(self, data, key):
        super(DesEncode, self).__init__()
        
        self.data = data
        self.key = key
    
    def progress_callback(self, progress: float):
        if int(progress * 100) % 5 == 0:
            self._progress_signal.emit(progress)

    def run(self):
        encoded = des_encode(self.data, self.key, self.progress_callback)
        base64_encoded = base64.encodebytes(BytesIO(binstr2bytes(encoded)).read())
        self._signal.emit(base64_encoded.decode())
        

class DesDecode(QThread):
    """
    DES decryption Thread
    """
    _signal = pyqtSignal(str)
    _progress_signal = pyqtSignal(float)
 
    def __init__(self, data, key):
        super(DesDecode, self).__init__()
        
        self.data = data
        self.key = key
    
    def progress_callback(self, progress: float):
        if int(progress * 100) % 5 == 0:
            self._progress_signal.emit(progress)

    def run(self):
        decoded = bin2str(
            des_decode(self.data, self.key, self.progress_callback), enc_n_bits=16).strip()
        self._signal.emit(decoded)


class DESapp(QWidget):
    """
    DES GUI class
    """
    def __init__(self) -> None:
        super().__init__()

        self.make_ui()
        self.set_onclick_listeners()

    def make_ui(self):
        """
        Build GUI components
        """
        # Content
        self.content_input_label = QLabel("Content", self)
        self.content_input_label.setGeometry(30, 40, 80, 30)
        self.content_edit = QTextEdit(self)
        self.content_edit.setGeometry(180, 40, 720, 140)

        self.enc_clear_btn = QPushButton("Clear", self)
        self.enc_clear_btn.setGeometry(940, 140, 120, 40)

        self.enc_file_edit = QLineEdit(self)
        self.enc_file_edit.setGeometry(180, 210, 300, 40)

        self.enc_bar = QProgressBar(self)
        self.enc_bar.setGeometry(500, 210, 280, 40)
        self.enc_bar.setMaximum(100) 
        self.enc_bar.setValue(0)

        self.select_contentf_btn = QPushButton("File", self)
        self.select_contentf_btn.setGeometry(780, 210, 120, 40)

        self.content_save_btn = QPushButton("Save", self)
        self.content_save_btn.setGeometry(940, 210, 120, 40)

        # Cipher
        self.encoded_input_label = QLabel("Cipher", self)
        self.encoded_input_label.setGeometry(30, 300, 80, 30)
        self.encoded_edit = QTextEdit(self)
        self.encoded_edit.setGeometry(180, 300, 720, 140)

        self.dec_clear_btn = QPushButton("Clear", self)
        self.dec_clear_btn.setGeometry(940, 400, 120, 40)

        self.dec_file_edit = QLineEdit(self)
        self.dec_file_edit.setGeometry(180, 470, 300, 40)

        self.dec_bar = QProgressBar(self)
        self.dec_bar.setGeometry(500, 470, 280, 40)
        self.dec_bar.setMaximum(100) 
        self.dec_bar.setValue(0)

        self.select_cipherf_btn = QPushButton("File", self)
        self.select_cipherf_btn.setGeometry(780, 470, 120, 40)

        self.cipher_save_btn = QPushButton("Save", self)
        self.cipher_save_btn.setGeometry(940, 470, 120, 40)

        self.key_input_label = QLabel("Key", self)
        self.key_input_label.setGeometry(30, 560, 80, 30)
        self.key_edit = QLineEdit(self)
        self.key_edit.setGeometry(180, 560, 300, 40)

        # Bottom buttons
        self.enc_btn = QPushButton("Encode", self)
        self.enc_btn.setGeometry(500, 560, 150, 40)

        self.dec_btn = QPushButton("Decode", self)
        self.dec_btn.setGeometry(750, 560, 150, 40)

        self.all_clear_btn = QPushButton("Clear", self)
        self.all_clear_btn.setGeometry(940, 560, 120, 40)

        # threads
        self.enc_th = None
        self.dec_th = None

        self.setGeometry(300, 300, 1080, 640)
        self.setWindowTitle('DES algorithm')    
        self.show()

    def set_onclick_listeners(self):
        """
        Set button event listener
        """
        self.enc_btn.clicked.connect(self.encode)
        self.dec_btn.clicked.connect(self.decode)
        self.enc_clear_btn.clicked.connect(self.clear_content)
        self.dec_clear_btn.clicked.connect(self.clear_encoded)
        self.all_clear_btn.clicked.connect(self.clear_all)
        self.select_contentf_btn.clicked.connect(self.select_content_f)
        self.select_cipherf_btn.clicked.connect(self.select_cipher_f)
        self.content_save_btn.clicked.connect(self.save_content_f)
        self.cipher_save_btn.clicked.connect(self.save_cipher_f)

    def check_content(self, content):
        """
        Check whether content is empty
        """
        if content == "":
            return "content is empty"
        return 0

    def check_encoded(self, encoded):
        """
        Check the validity of cipher
        """
        if len(encoded) % 64 != 0 or encoded == "":
            return "cipher incomplete or empty"
        try:
            for i in range(len(encoded) // 64):
                out = int(encoded[i*64:(i+1)*64], 2)
        except Exception as e:
            print(e)
            return "cipher can only contains zeros and ones"
        return 0

    def check_key(self, key):
        """
        Check whether a key is empty
        """
        if key == "":
            return "key shouldn't be empity"
        return 0

    def show_message(self, msg):
        """
        Show error message
        """
        QMessageBox.information(self, "Error", msg)

    def select_content_f(self):
        """
        Select content file
        """
        fname = QFileDialog.getOpenFileName(self, 'open content file', '/')
        if fname[0]:
            self.enc_file_edit.setText(fname[0])
            with open(fname[0], 'rb') as f_obj:
                base64_data = base64.b64encode(f_obj.read())
                self.content_edit.setText(base64_data.decode())

    def select_cipher_f(self):
        """
        Select cipher file"""
        fname = QFileDialog.getOpenFileName(self, 'open cipher file', '/')
        if fname[0]:
            self.dec_file_edit.setText(fname[0])
            with open(fname[0], 'rb') as f_obj:
                base64_data = base64.b64encode(f_obj.read())
                base64_text = ''.join(base64_data.decode().split("\n"))
                self.encoded_edit.setText(base64_text)

    def save_content_f(self):
        """
        Save content file
        """
        base64_data = None
        text = self.content_edit.toPlainText()
        try:
            base64_data = base64.b64decode(text.encode())
            fpath, type = QFileDialog.getSaveFileName(self, "save file", '/')
            with open(fpath, "wb") as f:
                f.write(base64_data)
        except:
            pass

    def save_cipher_f(self):
        """
        Save cipher file
        """
        base64_data = None
        cipher = self.encoded_edit.toPlainText()
        try:
            base64_data = base64.decodebytes(cipher.encode())
            fpath, type = QFileDialog.getSaveFileName(self, "save file", '/', 'des(*.des)')
            with open(fpath, "wb") as f:
                f.write(base64_data)
        except:
            self.show_message("cipher string incomplete")

    def encode(self):
        """
        Encryption
        """
        content = self.content_edit.toPlainText()
        response = self.check_content(content)
        if response == 0:
            key = self.key_edit.text()
            response2 = self.check_key(key)
            if response2 == 0:
                self.enc_th = DesEncode(content, key)
                self.enc_th._signal.connect(self.handle_enc_signal)
                self.enc_th._progress_signal.connect(self.handle_enc_bar_signal)
                self.enc_th.start()
            else:
                self.show_message(response2)
        else:
            self.show_message(response)

    def handle_enc_signal(self, encoded):
        """
        Encryption finish signal handler
        """
        self.encoded_edit.setText(encoded)

    def handle_enc_bar_signal(self, prog):
        """
        Encryption Progress bar handler
        """
        self.enc_bar.setValue(int(prog * 100))

    def decode(self):
        """
        Decryption
        """
        encoded = self.encoded_edit.toPlainText()
        try:
            encoded = bytes2binstr(base64.decodebytes(encoded.encode()))
        except:
            self.show_message("base64 cipher incomplete")
        response = self.check_encoded(encoded)
        if response == 0:
            key = self.key_edit.text()
            response2 = self.check_key(key)
            if response2 == 0:
                self.dec_th = DesDecode(encoded, key)
                self.dec_th._signal.connect(self.handle_dec_signal)
                self.dec_th._progress_signal.connect(self.handle_dec_bar_signal)
                self.dec_th.start()
            else:
                self.show_message(response2)
        else:
            self.show_message(response)

    def handle_dec_signal(self, decoded):
        """
        Decryption finish signal handler
        """
        self.content_edit.setText(decoded)

    def handle_dec_bar_signal(self, prog):
        """
        Decryption Progress bar handler
        """
        self.dec_bar.setValue(int(prog * 100))

    def clear_content(self):
        self.content_edit.setText("")
        self.enc_file_edit.setText("")
        self.enc_bar.setValue(0)

    def clear_encoded(self):
        self.encoded_edit.setText("")
        self.dec_file_edit.setText("")
        self.dec_bar.setValue(0)

    def clear_all(self):
        self.clear_content()
        self.clear_encoded()
        self.key_edit.setText("")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = DESapp()
    sys.exit(app.exec_())