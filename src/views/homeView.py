from PyQt5 import QtWidgets, uic
import sys
import string
import random
import os
import binascii
import vigenere
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class HomeView(QtWidgets.QMainWindow):
    def __init__(self):
        super(HomeView, self).__init__()  # Call the inherited classes __init__ method
        dirname = os.path.dirname(__file__)
        gui_file = os.path.join(dirname, 'gui/homeView.ui')
        uic.loadUi(gui_file, self)  # Load the .ui file

        self.selected_palette = self.caesar_button.palette()
        self.base_palette = self.vigenere_button.palette()

        self.plaintextEdit.textChanged.connect(self.show_encryption)
        self.ciphertextEdit.textChanged.connect(self.show_decryption)
        self.apply_param_button.clicked.connect(self.apply_parameters)

        #caesar cipher widgets
        self.caesar_button.clicked.connect(self.set_selected_caesar)
        self.shift_increase_button.clicked.connect(self.increase_shift)
        self.shift_decrease_button.clicked.connect(self.decrease_shift)
        self.shift=13
        self.shift_label.setText("13")

        #vigenere cipher widgets
        self.vigenere_button.clicked.connect(self.set_selected_vigenere)
        self.vigenere_key="sharper"
        self.vigenere_key_textEdit.setPlainText("sharper")

        #playfair cipher widgets
        self.playfair_button.clicked.connect(self.set_selected_playfair)
        self.playfair_key="sharper"
        self.playfair_key_textEdit.setPlainText("sharper")

        #aes_cbc cipher widgets
        self.aes_cbc_button.clicked.connect(self.set_selected_aes_cbc)
        self.generate_key_button.clicked.connect(self.change_aes_key)
        self.aes_key=get_random_bytes(32)
        self.aes_key_label.setText(binascii.hexlify(self.aes_key).decode())

        #aes_cbc cipher widgets
        self.aes_ctr_button.clicked.connect(self.set_selected_aes_ctr)
        self.generate_iv_button.clicked.connect(self.change_aes_iv)
        self.aes_iv=get_random_bytes(16)
        self.aes_iv_label.setText(binascii.hexlify(self.aes_iv).decode())

        #otp widgets
        self.otp_button.clicked.connect(self.set_selected_otp)
        self.otp_key = self.generate_random_key(1000)
        self.otp_key_label.setText(binascii.hexlify(self.otp_key).decode())

        #setting initial cipher
        self.set_selected_caesar()


    #----Definisco qui tutti i metodi di cifratura e decifratura-------
    def caesar_cipher(self, text, shift):
        result = []
        
        for char in text:
            if char.isalpha():
                # Determine whether the character is uppercase or lowercase
                if char.isupper():
                    alphabet = string.ascii_uppercase
                else:
                    alphabet = string.ascii_lowercase
                
                # Apply the Caesar cipher shift
                index = (alphabet.index(char) + shift) % 26
                encrypted_char = alphabet[index]
                
                # Preserve the case (uppercase/lowercase)
                if char.isupper():
                    result.append(encrypted_char.upper())
                else:
                    result.append(encrypted_char)
            else:
                # If the character is not a letter, leave it unchanged
                result.append(char)
        
        return ''.join(result)

    def rot13_encrypt(self, plaintext):
        return self.caesar_cipher(plaintext, self.shift)

    def rot13_decrypt(self, ciphertext):
        return self.caesar_cipher(ciphertext, -self.shift)

    def aes_cbc_encrypt(self, plaintext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        if len(plaintext.encode('utf-8')) % 16:
            plaintext = pad(plaintext.encode('utf-8'), 16)
        else:
            plaintext = plaintext.encode('utf-8')    
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = binascii.hexlify(ciphertext).decode()
        return ciphertext
        
    def aes_cbc_decrypt(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext=ciphertext.encode('utf-8')
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[16:])
        return plaintext.rstrip(b"\0")

    def aes_ctr_encrypt(self, plaintext):
        cipher = AES.new(self.aes_key, AES.MODE_CTR)
        plaintext = plaintext.encode('utf-8')    
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = binascii.hexlify(ciphertext).decode()
        return ciphertext
    
    def aes_ctr_decrypt(self, ciphertext) -> str:
        cipher = AES.new(self.aes_key, AES.MODE_CTR)
        ciphertext = binascii.unhexlify(self.ciphertextEdit.toPlainText().encode())
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')

    #def vigenere_encrypt(self, plaintext):

    def vigenere_encrypt(self, plaintext):
        encrypted_text = ""
        key_length = len(self.vigenere_key)
        
        for i in range(len(plaintext)):
            char = plaintext[i]
            key_char = self.vigenere_key[i % key_length]  # Repeating the key if it's shorter than the plaintext
            
            if char.isalpha():
                shift = ord(key_char) - ord('A') if key_char.isupper() else ord(key_char) - ord('a')
                if char.isupper():
                    encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
                else:
                    encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        
        return encrypted_text

    def vigenere_decrypt(self, ciphertext):
        decrypted_text = ""
        key_length = len(self.vigenere_key)
        
        for i in range(len(ciphertext)):
            char = ciphertext[i]
            key_char = key[i % key_length]  # Repeating the key if it's shorter than the ciphertext
            
            if char.isalpha():
                shift = ord(key_char) - ord('A') if key_char.isupper() else ord(key_char) - ord('a')
                if char.isupper():
                    decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
                else:
                    decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        
        return decrypted_text

    #def playfair_decrypt(self, ciphertext):

    def prepare_message(self, message):
        # Remove spaces and convert to uppercase
        message = message.replace(" ", "").upper()
        # Replace 'J' with 'I' since Playfair doesn't use 'J'
        message = message.replace("J", "I")
        return message

    def generate_key_table(self):
        key = self.prepare_message(self.playfair_key)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Playfair excludes 'J'
        key_table = []
        for char in key:
            if char not in key_table:
                key_table.append(char)
        for char in alphabet:
            if char not in key_table:
                key_table.append(char)
        return key_table

    def generate_matrix(self, key_table):
        matrix = [key_table[i:i + 5] for i in range(0, 25, 5)]
        self.playfair_matrix = matrix
        self.show_pf_matrix()
        return matrix

    def find_position(self, matrix, char):
        for row in range(5):
            if char in matrix[row]:
                col = matrix[row].index(char)
                return row, col

    def playfair_encrypt(self, message):
        message = self.prepare_message(message)
        key_table = self.generate_key_table()
        matrix = self.generate_matrix(key_table)
        encrypted_text = ""
        i = 0
        while i < len(message)-1:
            char1 = message[i]
            char2 = message[i + 1]
            row1, col1 = self.find_position(matrix, char1)
            row2, col2 = self.find_position(matrix, char2)
            if row1 == row2:
                encrypted_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:
                encrypted_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            else:
                encrypted_text += matrix[row1][col2] + matrix[row2][col1]
            i += 2
        return encrypted_text

    def playfair_decrypt(self, ciphertext):
        key_table = self.generate_key_table()
        matrix = self.generate_matrix(key_table)
        decrypted_text = ""
        i = 0
        while i < len(ciphertext):
            char1 = ciphertext[i]
            char2 = ciphertext[i + 1]
            row1, col1 = self.find_position(matrix, char1)
            row2, col2 = self.find_position(matrix, char2)
            if row1 == row2:
                decrypted_text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:
                decrypted_text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else:
                decrypted_text += matrix[row1][col2] + matrix[row2][col1]
            i += 2
        return decrypted_text

    #def otp_encrypt(self, plainext):

    def generate_random_key(self, length):
        # Generate a random key consisting of random bytes
        return bytes([random.randint(0, 255) for _ in range(length)])

    def otp_encrypt(self, plaintext):
        # Ensure the key length matches the plaintext length
        #if len(plaintext) != len(self.otp_key):
        #    raise ValueError("Plaintext and key must have the same length")
        # Perform XOR operation between plaintext and key to produce ciphertext
        plaintext=plaintext.encode('utf-8')
        ciphertext = bytes([plain_byte ^ key_byte for plain_byte, key_byte in zip(plaintext, self.otp_key[0:len(plaintext)])])
        return binascii.hexlify(ciphertext).decode()

    def otp_decrypt(self, ciphertext):
        # ensure the key length matches the ciphertext length
        #if len(ciphertext) != len(self.otp_key):
        #    raise ValueError("Ciphertext and key must have the same length")
        # Perform XOR operation between ciphertext and key to recover plaintext
        plaintext = bytes([cipher_byte ^ key_byte for cipher_byte, key_byte in zip(ciphertext, self.otp_key)])
        return plaintext

    #----Qui invece gestisco le azioni dei buttons


    def hide_widgets(self):
        #caesar
        self.shift_label.hide()
        self.shift_desc_label.hide()
        self.shift_increase_button.hide()
        self.shift_decrease_button.hide()
        #vigenere
        self.vigenere_key_textEdit.hide()
        self.vigenere_key_label.hide()
        #playfair
        self.playfair_key_textEdit.hide()
        self.playfair_key_label.hide()
        self.hide_table()
        #aes-ctr
        self.aes_key_label.hide()
        self.aes_key_desc_label.hide()
        self.generate_key_button.hide()
        #aes-cbc
        self.aes_iv_label.hide()
        self.aes_iv_desc_label.hide()
        self.generate_iv_button.hide()
        #otp
        self.otp_key_label.hide()
        self.otp_key_desc_label.hide()
        self.dots_label.hide()

    def change_aes_iv(self):
        self.aes_iv=get_random_bytes(16)
        self.aes_iv_label.setText(binascii.hexlify(self.aes_iv).decode())

    def change_aes_key(self):
        self.aes_key=get_random_bytes(32)
        self.aes_key_label.setText(binascii.hexlify(self.aes_key).decode())

    def increase_shift(self):
        self.shift=self.shift+1
        self.shift=self.shift%26
        self.shift_label.setText(str(self.shift))

    def decrease_shift(self):
        self.shift=self.shift-1
        self.shift=self.shift%26
        self.shift_label.setText(str(self.shift))

    def empy_textEdit(self):
        self.plaintextEdit.blockSignals(True)
        self.ciphertextEdit.blockSignals(True)
        self.plaintextEdit.setText("")
        self.ciphertextEdit.setText("")
        self.plaintextEdit.blockSignals(False)
        self.ciphertextEdit.blockSignals(False)

    def show_encryption(self):
        self.ciphertextEdit.blockSignals(True)
        self.ciphertextEdit.setText(self.encryption_algorithm(self.plaintextEdit.toPlainText()))
        self.ciphertextEdit.blockSignals(False)

    def show_decryption(self):
        self.plaintextEdit.blockSignals(True)
        self.plaintextEdit.setText(self.decryption_algorithm(self.ciphertextEdit.toPlainText()))
        self.plaintextEdit.blockSignals(False)

    def set_selected_caesar(self):
        self.set_all_palettes()
        self.caesar_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.rot13_encrypt
        self.decryption_algorithm=self.rot13_decrypt
        self.hide_widgets()
        self.shift_label.show()
        self.shift_desc_label.show()
        self.shift_increase_button.show()
        self.shift_decrease_button.show()
        self.show_encryption()

    def set_selected_vigenere(self):
        self.set_all_palettes()
        self.vigenere_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.vigenere_encrypt
        self.decryption_algorithm=self.vigenere_decrypt
        self.show_encryption()
        self.hide_widgets()
        self.vigenere_key_textEdit.show()
        self.vigenere_key_label.show()

    def set_selected_playfair(self):
        self.set_all_palettes()
        self.playfair_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.playfair_encrypt
        self.decryption_algorithm=self.playfair_decrypt
        self.show_encryption()
        self.hide_widgets()
        self.playfair_key_textEdit.show()
        self.playfair_key_label.show()
        self.show_table()
        self.show_pf_matrix()


    def set_selected_aes_cbc(self):
        self.set_all_palettes()
        self.aes_cbc_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.aes_cbc_encrypt
        self.decryption_algorithm=self.aes_cbc_decrypt
        self.show_encryption()
        self.hide_widgets()
        self.aes_iv_label.show()
        self.aes_iv_desc_label.show()
        self.generate_iv_button.show()
        self.aes_key_label.show()
        self.aes_key_desc_label.show()
        self.generate_key_button.show()

    def set_selected_aes_ctr(self):
        self.set_all_palettes()
        self.aes_ctr_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.aes_ctr_encrypt
        self.decryption_algorithm=self.aes_ctr_decrypt
        self.show_encryption()
        self.hide_widgets()
        self.aes_key_label.show()
        self.aes_key_desc_label.show()
        self.generate_key_button.show()
    
    def set_selected_otp(self):
        self.set_all_palettes()
        self.otp_button.setPalette(self.selected_palette)
        self.encryption_algorithm=self.otp_encrypt
        self.decryption_algorithm=self.otp_decrypt
        self.show_encryption()
        self.hide_widgets()
        self.otp_key_label.show()
        self.otp_key_desc_label.show()
        self.dots_label.show()

    def apply_parameters(self):
        self.shift=self.shift
        self.playfair_key=self.playfair_key_textEdit.toPlainText()
        self.vigenere_key=self.vigenere_key_textEdit.toPlainText()
        self.show_encryption()

    def set_all_palettes(self):
        self.caesar_button.setPalette(self.base_palette)
        self.vigenere_button.setPalette(self.base_palette)
        self.playfair_button.setPalette(self.base_palette)
        self.aes_cbc_button.setPalette(self.base_palette)
        self.aes_ctr_button.setPalette(self.base_palette)
        self.otp_button.setPalette(self.base_palette)

    def show_pf_matrix(self):
        self.pf_label_00.setText(self.playfair_matrix[0][0])
        self.pf_label_01.setText(self.playfair_matrix[0][1])
        self.pf_label_02.setText(self.playfair_matrix[0][2])
        self.pf_label_03.setText(self.playfair_matrix[0][3])
        self.pf_label_04.setText(self.playfair_matrix[0][4])
        self.pf_label_10.setText(self.playfair_matrix[1][0])
        self.pf_label_11.setText(self.playfair_matrix[1][1])
        self.pf_label_12.setText(self.playfair_matrix[1][2])
        self.pf_label_13.setText(self.playfair_matrix[1][3])
        self.pf_label_14.setText(self.playfair_matrix[1][4])
        self.pf_label_20.setText(self.playfair_matrix[2][0])
        self.pf_label_21.setText(self.playfair_matrix[2][1])
        self.pf_label_22.setText(self.playfair_matrix[2][2])
        self.pf_label_23.setText(self.playfair_matrix[2][3])
        self.pf_label_24.setText(self.playfair_matrix[2][4])
        self.pf_label_30.setText(self.playfair_matrix[3][0])
        self.pf_label_31.setText(self.playfair_matrix[3][1])
        self.pf_label_32.setText(self.playfair_matrix[3][2])
        self.pf_label_33.setText(self.playfair_matrix[3][3])
        self.pf_label_34.setText(self.playfair_matrix[3][4])
        self.pf_label_40.setText(self.playfair_matrix[4][0])
        self.pf_label_41.setText(self.playfair_matrix[4][1])
        self.pf_label_42.setText(self.playfair_matrix[4][2])
        self.pf_label_43.setText(self.playfair_matrix[4][3])
        self.pf_label_44.setText(self.playfair_matrix[4][4])

    def hide_table(self):
        self.pf_label_00.hide()
        self.pf_label_01.hide()
        self.pf_label_02.hide()        
        self.pf_label_03.hide()
        self.pf_label_04.hide()    #def show_info(self):
        self.pf_label_10.hide()        #self.vista_home=VistaHome()
        self.pf_label_11.hide()        #self.vista_home.show()
        self.pf_label_12.hide()        #self.close()
        self.pf_label_13.hide()        #hi = 1
        self.pf_label_14.hide()
        self.pf_label_20.hide()
        self.pf_label_21.hide()
        self.pf_label_22.hide()
        self.pf_label_23.hide()
        self.pf_label_24.hide()
        self.pf_label_30.hide()
        self.pf_label_31.hide()
        self.pf_label_32.hide()
        self.pf_label_33.hide()
        self.pf_label_34.hide()
        self.pf_label_40.hide()
        self.pf_label_41.hide()
        self.pf_label_42.hide()
        self.pf_label_43.hide()
        self.pf_label_44.hide()

    def show_table(self):
        self.pf_label_00.show()
        self.pf_label_01.show()        
        self.pf_label_02.show()
        self.pf_label_03.show()    #def show_info(self):
        self.pf_label_04.show()        # Metodo per visualizzare 'VistaHome'
        self.pf_label_10.show()        #self.vista_home=VistaHome()
        self.pf_label_11.show()        #self.vista_home.show()
        self.pf_label_12.show()        #self.close()
        self.pf_label_13.show()        #hi = 1
        self.pf_label_14.show()
        self.pf_label_20.show()
        self.pf_label_21.show()
        self.pf_label_22.show()
        self.pf_label_23.show()
        self.pf_label_24.show()
        self.pf_label_30.show()
        self.pf_label_31.show()
        self.pf_label_32.show()
        self.pf_label_33.show()
        self.pf_label_34.show()
        self.pf_label_40.show()
        self.pf_label_41.show()
        self.pf_label_42.show()
        self.pf_label_43.show()
        self.pf_label_44.show()
