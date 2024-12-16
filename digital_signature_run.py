# -*- coding: utf-8 -*-
import sys
import hashlib

from Crypto.Hash import SHA256
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox
from PyQt5.uic import loadUiType
from PyQt5.QtCore import pyqtSlot
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from digital_signature import Ui_Dialog


class SignatureDialog(QDialog, Ui_Dialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # 连接按钮点击信号到槽函数
        self.Choose_File.clicked.connect(self.select_multiple_files)
        self.signature.clicked.connect(self.sign_files)
        self.verify.clicked.connect(self.verify_signatures)

        # 存储私钥和公钥文件路径的属性
        self.private_key_path = ""
        self.public_key_path = ""

        # 连接选择密钥文件的按钮到槽函数
        self.choose_private_key_btn.clicked.connect(self.select_private_key)
        self.choose_public_key_btn.clicked.connect(self.select_public_key)

    def select_multiple_files(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, "选择文件", "/",
                                                    "所有文件 (*);;PDF 文件 (*.pdf);;文本文件 (*.txt);;Docx 文件 (*.docx)")
        if file_paths:
            self.textEdit.setPlainText("\n".join(file_paths))

    @pyqtSlot()
    def calculate_sha256(self):  # 修改函数名及算法
        """计算所选文件的SHA-256摘要"""
        file_paths = self.textEdit.toPlainText().splitlines()
        result_text = ""
        for file_path in file_paths:
            sha256_hash = hashlib.sha256()  # 使用SHA-256
            try:
                with open(file_path.strip(), 'rb') as file:
                    for chunk in iter(lambda: file.read(4096), b''):
                        sha256_hash.update(chunk)
                result_text += f"文件 {file_path} 的SHA-256摘要: {sha256_hash.hexdigest()} \n"
            except FileNotFoundError:
                result_text += f"文件 {file_path} 不存在，无法计算摘要\n"
            except Exception as e:
                result_text += f"计算文件 {file_path} 摘要时出错: {str(e)}\n"
        self.textEdit.setPlainText(result_text)

    def select_private_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "选择私钥文件", "/",
                                                  "所有文件 (*)")
        if key_path:
            self.private_key_path = key_path
            self.textEdit_2.setPlainText(key_path)

    def select_public_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "选择公钥文件", "/",
                                                  "所有文件 (*)")
        if key_path:
            self.public_key_path = key_path
            self.textEdit_3.setPlainText(key_path)

    def sign_files(self):
        file_paths = self.textEdit.toPlainText().splitlines()
        if not self.private_key_path:
            QMessageBox.information(self, "提示","请先选择私钥文件")
            return
        digests = []  # 用于存储每个文件的SHA-256摘要
        signatures = []
        for file_path in file_paths:
            sha256_digest = self.get_sha256_digest(file_path)  # 修改为获取SHA-256摘要
            if sha256_digest:
                digests.append(sha256_digest.hex())  # 将摘要转换为十六进制字符串并保存
                with open(self.private_key_path, 'rb') as key_file:
                    private_key = RSA.import_key(key_file.read())
                hash_object = SHA256.new(sha256_digest)  # 使用Crypto.Hash.SHA256创建哈希对象
                signer = pkcs1_15.new(private_key)
                try:
                    signature = signer.sign(hash_object)
                    signatures.append(signature)
                except Exception as e:
                    QMessageBox.critical(self, "错误",f"对文件 {file_path} 签名时出错: {str(e)}")
        self.signatures = signatures
        # 准备显示摘要值的消息
        digest_messages = ["\n文件: {} \n SHA-256摘要: {}".format(file_path, digest) for file_path, digest in
                           zip(file_paths, digests)]
        digest_summary = "".join(digest_messages)
        if signatures:
            QMessageBox.information(self, "执行结果", "数字签名生成成功！\n" + digest_summary)
        else:
            QMessageBox.critical(self, "错误","数字签名生成失败，请检查相关设置及文件选择")

    def verify_signatures(self):
        file_paths = self.textEdit.toPlainText().splitlines()
        if not self.public_key_path:
            QMessageBox.information(self, "提示","请先选择公钥文件")
            return
        if not hasattr(self, 'signatures'):
            QMessageBox.critical(self, "错误","请先进行数字签名操作")
            return
        all_verified = True
        digests = []  # 用于存储每个文件的SHA-256摘要（十六进制字符串）

        for index, file_path in enumerate(file_paths):
            sha256_digest = self.get_sha256_digest(file_path)  # 修改为获取SHA-256摘要
            if sha256_digest:
                digests.append(sha256_digest.hex())  # 将摘要转换为十六进制字符串并保存
                with open(self.public_key_path, 'rb') as key_file:
                    public_key = RSA.import_key(key_file.read())
                hash_object = SHA256.new(sha256_digest)  # 使用Crypto.Hash.SHA256创建哈希对象，与签名时保持一致
                verifier = pkcs1_15.new(public_key)
                try:
                    verifier.verify(hash_object, self.signatures[index])
                except (ValueError, TypeError):
                    all_verified = False
                    QMessageBox.critical(self, "错误",f"文件 {file_path} 的签名验证失败")
            # 准备显示摘要值和验证结果的消息
            digest_messages = [f"\n文件: {file_path} \n SHA-256摘要: {digest}" for file_path, digest in
                                   zip(file_paths, digests)]
            digest_summary = "".join(digest_messages)
        if all_verified:
            QMessageBox.information(self, "验证结果", "所有文件的签名验证成功!\n" + digest_summary)
        else:
            QMessageBox.critical(self, "错误","部分文件的签名验证失败，请检查相关文件及操作")

    def get_sha256_digest(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path.strip(), 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.digest()
        except FileNotFoundError:
            QMessageBox.critical(self, "错误",f"文件 {file_path} 不存在，无法计算摘要")
            return None
        except Exception as e:
            QMessageBox.critical(self, "错误",f"计算文件 {file_path} 摘要时出错: {str(e)}")
            return None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    signature_window = SignatureDialog()
    signature_window.show()
    sys.exit(app.exec_())
