# -*- coding: gb2312 -*-
import sys
from PyQt5.QtWidgets import QApplication, QDialog , QFileDialog, QMessageBox
from PyQt5.uic import loadUiType
from Key_create import Ui_Dialog
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os


class Key_Dialog(QDialog, Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # 将按钮的点击信号与自定义的槽函数进行连接
        self.Create_randomAES_key.clicked.connect(self.Randomkey_create)
        self.Create_RSA_key.clicked.connect(self.RSAkey_create)

        
    def Randomkey_create(self):
        try:
            # 弹出选择文件夹对话框
            dir_path = QFileDialog.getExistingDirectory(self, "选择保存密钥的文件夹")
            if dir_path:
                # 生成AES-192随机密钥（24字节）
                key = get_random_bytes(24)
                key_file_path = os.path.join(dir_path, "random_aes_192_key.bin")
                with open(key_file_path, 'wb') as f:
                    f.write(key)
                QMessageBox.information(self, "提示", "密钥文件输出成功")
        except Exception as e:
            print(f"生成随机AES密钥时出现错误: {str(e)}")
            
    def RSAkey_create(self):
        try:
            key = RSA.generate(2048)

            # 导出私钥和公钥
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            dir_path = QFileDialog.getExistingDirectory(self, "选择保存密钥的文件夹")
            if dir_path:
                # 保存私钥和公钥到PEM文件（使用不同的文件名）
                key_file_path = os.path.join(dir_path, "private_key.pem")
                with open(key_file_path, 'wb') as f:
                    f.write(private_key)
                key_file_path = os.path.join(dir_path, "public_key.pem")
                with open(key_file_path, 'wb') as f:
                    f.write(public_key)
                QMessageBox.information(self, "提示", "密钥文件输出成功")
        except Exception as e:
            print(f"生成RSA密钥时出现错误: {str(e)}")
            
if __name__ == "__main__":
    app = QApplication(sys.argv)
    AES_Windows = Key_Dialog()
    AES_Windows.show()
    sys.exit(app.exec_())