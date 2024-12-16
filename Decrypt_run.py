# -*- coding: gb2312 -*-
import sys
from PyQt5.QtWidgets import QApplication, QDialog , QMainWindow, QFileDialog, QMessageBox, QInputDialog
from PyQt5.uic import loadUiType
from Decrypt import Ui_Dialog
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os


class De_Dialog(QDialog, Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # 将按钮的点击信号与自定义的槽函数进行连接
        
        #解密密钥
        self.Choose_keyFile.clicked.connect(self.Select_multiple_files)
        self.Decrypt_key.clicked.connect(self.RSA_Decrypt_keys)
        
        #解密文件
        self.Choose_File.clicked.connect(self.Select_multiple_files_2)
        self.Decrypt_file.clicked.connect(self.AES_Decrypt_files)



    def Select_multiple_files(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "/", "All Files (*);;PDF Files (*.pdf);;Text Files (*.txt);;Docx Files (*.docx)")
        if file_paths:
            file_list_text = "\n".join(file_paths)  # 将文件路径列表转换为字符串，每个文件路径占一行
            self.keyEdit.setPlainText(file_list_text)  # 将字符串内容设置到QTextEdit中显示
    def Select_multiple_files_2(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "/", "All Files (*);;PDF Files (*.pdf);;Text Files (*.txt);;Docx Files (*.docx)")
        if file_paths:
            file_list_text = "\n".join(file_paths)  # 将文件路径列表转换为字符串，每个文件路径占一行
            self.fileEdit.setPlainText(file_list_text)  # 将字符串内容设置到QTextEdit中显示

            
    def AES_Decrypt_files(self):
        # 弹出文件选择对话框，让用户选择密钥文件
        key_file_path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "", "Key Files (*.bin);;All Files (*)")
        if key_file_path:
            try:
                with open(key_file_path, 'rb') as key_file:
                    key = key_file.read()
                if len(key) not in [16, 24, 32]:  # 检查密钥长度是否符合AES标准（16、24、32字节分别对应AES-128、AES-192、AES-256）
                    QMessageBox.warning(self, "错误", "密钥长度不符合AES标准，请选择正确的密钥文件")
                    return
                file_paths_text = self.fileEdit.toPlainText()
                file_paths = file_paths_text.splitlines()
                for file_path in file_paths:
                    if file_path:
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()
                        cipher = AES.new(key, AES.MODE_ECB)
                        # 先进行解密操作
                        decrypted_data = cipher.decrypt(encrypted_data)
                        # 获取填充的字节数（最后一个字节表示填充的字节数）
                        padding_length = decrypted_data[-1]
                        # 验证填充长度是否合法
                        if padding_length < 1 or padding_length > AES.block_size:
                            raise ValueError("无效的填充长度")
                        # 验证填充内容是否正确（按照PKCS7规则，末尾填充的字节都应该是填充长度值对应的字节）
                        expected_padding = bytes([padding_length]) * padding_length
                        if decrypted_data[-padding_length:]!= expected_padding:
                            raise ValueError("填充验证失败")
                        # 去除填充字节得到真正的解密数据
                        decrypted_data = decrypted_data[:-padding_length]
                        dir_name = os.path.dirname(file_path)
                        file_name_without_ext = os.path.splitext(os.path.basename(file_path))[0]
                        decrypted_file_name = file_name_without_ext + '_decrypted' + os.path.splitext(file_path)[1]
                        decrypted_file_path = os.path.join(dir_name, decrypted_file_name)
                        with open(decrypted_file_path, 'wb') as f:
                            f.write(decrypted_data)
                # 所有文件解密完成后，弹出提示弹窗告知用户
                QMessageBox.information(self, "提示", "文件解密已完成")
            except FileNotFoundError:
                QMessageBox.warning(self, "错误", "指定的文件不存在，请重新选择")
            except ValueError as ve:
                QMessageBox.warning(self, "错误", f"解密过程出现错误: {str(ve)}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"解密过程出现错误: {str(e)}")
        else:
            QMessageBox.warning(self, "提示", "请选择密钥文件后再进行解密操作")
            


    def RSA_Decrypt_keys(self):
        encrypted_key_file_paths_text = self.keyEdit.toPlainText()
        encrypted_key_file_paths = encrypted_key_file_paths_text.splitlines()
        if not encrypted_key_file_paths:
            QMessageBox.warning(self, "提示", "请先选择要解密的加密AES密钥文件")
            return
        # 弹出文件选择对话框，让用户选择RSA私钥文件
        rsa_private_key_file_path, _ = QFileDialog.getOpenFileName(self, "选择RSA私钥文件", "", "RSA Private Key Files (*.pem);;All Files (*)")
        if not rsa_private_key_file_path:
            QMessageBox.warning(self, "提示", "请选择RSA私钥文件后再进行解密操作")
            return
        try:
            with open(rsa_private_key_file_path, 'rb') as rsa_private_key_file:
                rsa_private_key = RSA.import_key(rsa_private_key_file.read())
            rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
            for encrypted_key_file_path in encrypted_key_file_paths:
                if encrypted_key_file_path:
                    with open(encrypted_key_file_path, 'rb') as encrypted_key_file:
                        encrypted_aes_key_data = encrypted_key_file.read()
                    try:
                        decrypted_aes_key_data = rsa_cipher.decrypt(encrypted_aes_key_data)
                    except ValueError as e:
                        QMessageBox.warning(self, "错误", f"解密失败，可能是密钥不匹配或数据已损坏: {str(e)}")
                        continue
                    decrypted_key_file_name = os.path.basename(encrypted_key_file_path).replace('.encrypted', '')
                    decrypted_key_file_path = os.path.join(os.path.dirname(encrypted_key_file_path), decrypted_key_file_name)
                    with open(decrypted_key_file_path, 'wb') as decrypted_key_file:
                        decrypted_key_file.write(decrypted_aes_key_data)
            QMessageBox.information(self, "提示", "AES密钥文件解密已完成")
        except FileNotFoundError as e:
            QMessageBox.warning(self, "错误", f"文件不存在错误: {str(e)}")
        except ValueError as e:
            QMessageBox.warning(self, "错误", f"密钥格式或解密操作错误: {str(e)}")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"解密过程出现未知错误: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    Encrypt_windows = De_Dialog()
    Encrypt_windows.show()
    sys.exit(app.exec_())
    


 
 