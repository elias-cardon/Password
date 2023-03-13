import hashlib
import re
import tkinter as tk
from tkinter import messagebox

class PasswordValidatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Validation et cryptage de mot de passe")

        self.validation_frame = tk.Frame(self.master, padx=10, pady=10)
        self.validation_frame.pack()

        self.password_label = tk.Label(self.validation_frame, text="Mot de passe : ")
        self.password_label.grid(row=0, column=0, sticky='w')

        self.password_entry = tk.Entry(self.validation_frame, show="*")
        self.password_entry.grid(row=0, column=1)

        self.validate_button = tk.Button(self.validation_frame, text="Valider", command=self.validate_password)
        self.validate_button.grid(row=1, column=0, pady=10)

        self.encryption_frame = tk.Frame(self.master, padx=10, pady=10)
        self.encryption_frame.pack()

        self.encrypt_button = tk.Button(self.encryption_frame, text="Crypter", command=self.encrypt_password,
                                        state=tk.DISABLED)
        self.encrypt_button.grid(row=1, column=0, pady=10)

        self.message_label = tk.Label(self.master, text="")
        self.message_label.pack()

    def validate_password(self):
        password = self.password_entry.get()
        if len(password) == 0:
            messagebox.showerror("Erreur", "Veuillez entrer un mot de passe.")
            return

        while True:
            if len(password) < 8:
                messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 8 caractères.")
            elif not re.search("[a-z]", password):
                messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins une lettre minuscule.")
            elif not re.search("[A-Z]", password):
                messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins une lettre majuscule.")
            elif not re.search("[0-9]", password):
                messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins un chiffre.")
            elif not re.search("[!@#$%^&*()_+-={};':\"|,.<>?~`]", password):
                messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins un caractère spécial.")
            else:
                messagebox.showinfo("Succès", "Le mot de passe est valide.")
                self.encrypt_button.config(state=tk.NORMAL)
                break
            password = tk.simpledialog.askstring("Nouveau mot de passe", "Veuillez entrer un nouveau mot de passe : ", show='*')
            if password is None:
                break

    def encrypt_password(self):
        password = self.password_entry.get()
        hashed_password = hashlib.sha256(password.encode())
        encrypted_password = hashed_password.hexdigest()
        messagebox.showinfo("Succès", "Le mot de passe a été crypté avec succès : " + encrypted_password)

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordValidatorGUI(root)
    root.mainloop()
