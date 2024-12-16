# -*- coding: gb2312 -*-
import sys
from PyQt5.QtWidgets import QApplication, QDialog , QMainWindow, QFileDialog, QMessageBox, QInputDialog
from PyQt5.uic import loadUiType
from Encrypt import Ui_Dialog
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os


class En_Dialog(QDialog, Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # 将按钮的点击信号与自定义的槽函数进行连接
        #加密文件
        self.Choose_File.clicked.connect(self.Select_multiple_files)
        self.En_file.clicked.connect(self.AES_Encrypt_files)
        
        #加密密钥
        self.Choose_keyFile.clicked.connect(self.Select_multiple_files_2)
        self.En_key.clicked.connect(self.RSA_Encrypt_keys)
        


    def Select_multiple_files(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "/", "All Files (*);;PDF Files (*.pdf);;Text Files (*.txt);;Docx Files (*.docx)")
        if file_paths:
            file_list_text = "\n".join(file_paths)  # 将文件路径列表转换为字符串，每个文件路径占一行
            self.FileEdit.setPlainText(file_list_text)  # 将字符串内容设置到QTextEdit中显示
            

    def Select_multiple_files_2(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "/", "All Files (*);;PDF Files (*.pdf);;Text Files (*.txt);;Docx Files (*.docx)")
        if file_paths:
            file_list_text = "\n".join(file_paths)  # 将文件路径列表转换为字符串，每个文件路径占一行
            self.KeyEdit.setPlainText(file_list_text)  # 将字符串内容设置到QTextEdit中显示

    def AES_Encrypt_files(self):
    # 弹出文件选择对话框，让用户选择密钥文件
        key_file_path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "", "Key Files (*.bin);;All Files (*)")
        if key_file_path:
            try:
                with open(key_file_path, 'rb') as key_file:
                    key = key_file.read()
                if len(key) not in [16, 24, 32]:  # 检查密钥长度是否符合AES标准（16、24、32字节分别对应AES-128、AES-192、AES-256）
                    QMessageBox.warning(self, "错误", "密钥长度不符合AES标准，请选择正确的密钥文件")
                    return
                file_paths_text = self.FileEdit.toPlainText()
                file_paths = file_paths_text.splitlines()
                for file_path in file_paths:
                    if file_path:
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        cipher = AES.new(key, AES.MODE_ECB)
                        # 计算需要填充的字节数
                        padding_length = AES.block_size - (len(file_data) % AES.block_size)
                        if padding_length == 0:
                            padding_length = AES.block_size
                        # 创建填充字节串
                        padding = bytes([padding_length]) * padding_length
                        padded_data = file_data + padding
                        encrypted_data = cipher.encrypt(padded_data)
                        dir_name = os.path.dirname(file_path)
                        file_name_without_ext = os.path.splitext(os.path.basename(file_path))[0]
                        encrypted_file_name = file_name_without_ext + '_encrypted' + os.path.splitext(file_path)[1]
                        encrypted_file_path = os.path.join(dir_name, encrypted_file_name)
                        with open(encrypted_file_path, 'wb') as f:
                            f.write(encrypted_data)
                QMessageBox.information(self, "提示", "文件加密已完成")
            except FileNotFoundError:
                QMessageBox.warning(self, "错误", "指定的密钥文件不存在，请重新选择")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"加密过程出现错误: {str(e)}")
        else:
            QMessageBox.warning(self, "提示", "请选择密钥文件后再进行加密操作")
    

    def RSA_Encrypt_keys(self):
        key_file_paths_text = self.KeyEdit.toPlainText()
        key_file_paths = key_file_paths_text.splitlines()
        if not key_file_paths:
            QMessageBox.warning(self, "提示", "请先选择要加密的AES密钥文件")
            return
        # 弹出文件选择对话框，让用户选择RSA公钥文件
        rsa_public_key_file_path, _ = QFileDialog.getOpenFileName(self, "选择RSA公钥文件", "", "RSA Public Key Files (*.pem);;All Files (*)")
        if not rsa_public_key_file_path:
            QMessageBox.warning(self, "提示", "请选择RSA公钥文件后再进行加密操作")
            return
        try:
            with open(rsa_public_key_file_path, 'rb') as rsa_public_key_file:
                rsa_public_key = RSA.import_key(rsa_public_key_file.read())
            rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
            for key_file_path in key_file_paths:
                if key_file_path:
                    with open(key_file_path, 'rb') as key_file:
                        aes_key_data = key_file.read()
                    encrypted_aes_key_data = rsa_cipher.encrypt(aes_key_data)
                    encrypted_key_file_name = os.path.basename(key_file_path) + '.encrypted'
                    encrypted_key_file_path = os.path.join(os.path.dirname(key_file_path), encrypted_key_file_name)
                    with open(encrypted_key_file_path, 'wb') as encrypted_key_file:
                        encrypted_key_file.write(encrypted_aes_key_data)
            QMessageBox.information(self, "提示", "AES密钥文件加密已完成")
        except FileNotFoundError as e:
            QMessageBox.warning(self, "错误", f"文件不存在错误: {str(e)}")
        except ValueError as e:
            QMessageBox.warning(self, "错误", f"密钥格式或加密操作错误: {str(e)}")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"加密过程出现未知错误: {str(e)}")
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    AES_Windows = En_Dialog()
    AES_Windows.show()
    sys.exit(app.exec_())
    


 
 