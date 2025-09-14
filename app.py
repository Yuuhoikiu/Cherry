"""
Cherry!!!!!
"""
from PySide6 import QtWidgets

from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QFileDialog, QHBoxLayout, QComboBox, QTextEdit, QMessageBox, QLineEdit
from PySide6.QtCore import Qt
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
import sys
from PySide6 import QtWidgets

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    # Backwards compatibility - importlib.metadata was added in Python 3.8
    import importlib_metadata

class DecoderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.show()
        

    def initUI(self):
        self.setWindowTitle('cherry')
        self.setGeometry(100, 100, 800, 600)  # 增加窗口宽度以容纳更多内容

        
        

        # 中心窗口
        self.central_widget = QWidget()

        # 主布局
        main_layout = QHBoxLayout()

        # 左侧布局
        left_layout = QVBoxLayout()

        # 文件选择按钮
        self.file_button = QPushButton('选择文件', self)
        self.file_button.clicked.connect(self.open_file_dialog)
        left_layout.addWidget(self.file_button)

        # 编码选择下拉框
        self.encoding_label = QLabel('选择编码:', self)
        self.encoding_combo = QComboBox(self)
        self.encoding_combo.addItems(['utf-8', 'utf-16', 'iso-8859-1', 'gbk', 'big5', 'shift_jis'])
        left_layout.addWidget(self.encoding_label)
        left_layout.addWidget(self.encoding_combo)

        # 解码按钮
        self.decode_button = QPushButton('解码', self)
        self.decode_button.clicked.connect(self.decode_file)
        left_layout.addWidget(self.decode_button)

        # 状态标签
        self.status_label = QLabel('状态: 等待操作', self)
        left_layout.addWidget(self.status_label)

        # MD5校验和标签
        self.md5_label = QLabel('MD5校验和: -', self)
        left_layout.addWidget(self.md5_label)

        # RSA密钥生成按钮
        self.generate_keys_button = QPushButton('生成RSA密钥', self)
        self.generate_keys_button.clicked.connect(self.generate_keys)
        left_layout.addWidget(self.generate_keys_button)

        # RSA公钥输入
        self.public_key_label = QLabel('RSA公钥:', self)
        self.public_key_line_edit = QLineEdit(self)
        left_layout.addWidget(self.public_key_label)
        left_layout.addWidget(self.public_key_line_edit)

        # RSA私钥输入
        self.private_key_label = QLabel('RSA私钥:', self)
        self.private_key_line_edit = QLineEdit(self)
        left_layout.addWidget(self.private_key_label)
        left_layout.addWidget(self.private_key_line_edit)

        # RSA加密按钮
        self.encrypt_button = QPushButton('RSA加密', self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        left_layout.addWidget(self.encrypt_button)

        # RSA解密按钮
        self.decrypt_button = QPushButton('RSA解密', self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        left_layout.addWidget(self.decrypt_button)

        # 将左侧布局添加到主布局
        main_layout.addLayout(left_layout)

        # 右侧布局
        right_layout = QVBoxLayout()

        # 解码文本显示区域
        self.decoded_text_edit = QTextEdit()
        self.decoded_text_edit.setReadOnly(True)  # 设置为只读
        self.decoded_text_edit.setVisible(False)  # 默认不显示
                # 解码文本显示区域
        self.text_area = QTextEdit(self)
        self.text_area.append('欢迎使用Cherry软件，这是一款采用RSA加密算法的专业加密解决方案，可视为Babel软件的进阶版本。Cherry不仅提供了强大的加密功能，还集成了MD5哈希计算和文本解码技术。通过其高级的公钥与私钥自定义机制，Cherry不仅提升了安全性，还为用户带来了更为便捷的使用体验。                                                             Cherry开发者                                                       Welcome to Cherry Software, a professional encryption solution that leverages the RSA encryption algorithm, which can be considered an advanced version of Babel software if you are familiar with it. Cherry not only offers robust encryption capabilities but also integrates MD5 hash computation and text decoding technology. With its sophisticated customizable public and private key mechanisms, Cherry enhances security while providing a more user-friendly experience.   Cherry Developer')
        right_layout.addWidget(self.text_area)


        # 将右侧布局添加到主布局
        main_layout.addLayout(right_layout)

        # 将主布局添加到中心窗口
        self.central_widget.setLayout(main_layout)

        # 设置中心窗口
        self.setCentralWidget(self.central_widget)
        self.status_label.setText('状态: 等待操作。') 
        self.show()
       


    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        self.private_key_line_edit.setText(private_key.decode('utf-8'))
        self.public_key_line_edit.setText(public_key.decode('utf-8'))
        self.status_label.setText('状态: RSA密钥对已生成。')

    def open_file_dialog(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.status_label.setText(f'状态: 文件已选择 - {file_name}')
            self.calculate_md5()
        else:
            self.status_label.setText('状态: 请先选择文件')

    def encrypt_file(self):
        public_key = self.public_key_line_edit.text()
        if not public_key:
            QMessageBox.warning(self, '错误', '请输入有效的RSA公钥。')
            return
        if hasattr(self, 'file_path') and self.file_path:
            try:
                # 导入公钥
                public_key_obj = RSA.import_key(public_key)
                cipher = PKCS1_OAEP.new(public_key_obj)

                # 读取文件
                with open(self.file_path, 'rb') as file:
                    file_data = file.read()

                # 分块加密文件
                encrypted_data = b''
                block_size = 214  # RSA加密块大小通常是密钥长度减去11字节，此处假设为2048位密钥
                for i in range(0, len(file_data), block_size):
                    block = file_data[i:i + block_size]
                    encrypted_block = cipher.encrypt(block)
                    encrypted_data += encrypted_block

                encrypted_file_path = os.path.splitext(self.file_path)[0] + '.enc'
                with open(encrypted_file_path, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)
                QMessageBox.information(self, '成功', '文件加密成功。')
            except Exception as e:
                QMessageBox.warning(self, '错误', f'加密失败: {e}')

    def decrypt_file(self):
        private_key = self.private_key_line_edit.text()
        if not private_key:
            QMessageBox.warning(self, '错误', '请输入有效的RSA私钥。')
            return
        if hasattr(self, 'file_path') and self.file_path:
            try:
                # 导入私钥
                private_key_obj = RSA.import_key(private_key)
                cipher = PKCS1_OAEP.new(private_key_obj)

                # 读取加密文件
                with open(self.file_path, 'rb') as encrypted_file:
                    encrypted_data = encrypted_file.read()

                # 分块解密文件
                decrypted_data = b''
                block_size = 256  # RSA解密块大小通常与密钥长度相同，这里假设为256字节
                for i in range(0, len(encrypted_data), block_size):
                    encrypted_block = encrypted_data[i:i + block_size]
                    try:
                        decrypted_block = cipher.decrypt(encrypted_block)
                        decrypted_data += decrypted_block
                    except ValueError as e:
                        # 如果解密块时发生错误，可能是因为块是填充的，尝试去除填充
                        decrypted_block = unpad(decrypted_block, block_size)
                        decrypted_data += decrypted_block
                        break  # 假设文件末尾的填充块是最后一个块

                decrypted_file_path = os.path.splitext(self.file_path)[0] + '.dec'
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)
                QMessageBox.information(self, '成功', '文件解密成功。')
            except Exception as e:
                QMessageBox.warning(self, '错误', f'解密失败: {e}')

    def calculate_md5(self):
        if hasattr(self, 'file_path') and self.file_path:
            md5_hash = hashlib.md5()
            try:
                with open(self.file_path, 'rb') as file:
                    for chunk in iter(lambda: file.read(4096), b""):
                        md5_hash.update(chunk)
                md5_hex = md5_hash.hexdigest()
                self.md5_label.setText(f'MD5校验和: {md5_hex}')
            except IOError:
                self.md5_label.setText('状态: 文件读取错误')
        else:
            self.md5_label.setText('状态: 请先选择文件')

    def decode_file(self):
        target_encoding = self.encoding_combo.currentText()
        if hasattr(self, 'file_path') and self.file_path:
            # 调用解码函数并获取结果
            success, decoded_text = self.decode_text(self.file_path, target_encoding)
            if success:
                self.status_label.setText('状态: 解码成功')
                self.show_decoded_text(decoded_text)
            else:
                self.status_label.setText('状态: 解码失败')
        else:
            self.status_label.setText('状态: 请先选择文件')

    def decode_text(self, file_path, target_encoding):
        # 尝试解码文件，并返回成功与否以及解码后的文本
        try:
            with open(file_path, 'rb') as file:
                raw_data = file.read()
            text = raw_data.decode(target_encoding)
            return True, text
        except UnicodeDecodeError:
            return False, None

    def show_decoded_text(self, text):
        # 在同一个窗口中显示解码后的文本
        self.decoded_text_edit.setVisible(True)  # 显示文本编辑区域
        self.decoded_text_edit.setPlainText(text)  # 设置解码后的文本





def main():
    # Linux desktop environments use an app's .desktop file to integrate the app
    # in to their application menus. The .desktop file of this app will include
    # the StartupWMClass key, set to app's formal name. This helps associate the
    # app's windows to its menu item.
    #
    # For association to work, any windows of the app must have WMCLASS property
    # set to match the value set in app's desktop file. For PySide6, this is set
    # with setApplicationName().

    # Find the name of the module that was used to start the app
    app_module = sys.modules["__main__"].__package__
    # Retrieve the app's metadata
    metadata = importlib_metadata.metadata(app_module)

    QApplication.setApplicationName(metadata["Formal-Name"])

    app = QApplication(sys.argv)
    main_window = DecoderGUI()
    main_window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = DecoderGUI()
    main_window.show()  # 显示主窗口
    sys.exit(app.exec())
    
