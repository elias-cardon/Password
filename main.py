import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re
import hashlib

class PasswordValidatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Validation et cryptage de mot de passe")
        self.master.geometry("400x200")  # Agrandir la fenêtre à 400x200 pixels

        # Centre la fenêtre sur l'écran
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (400 / 2))
        y_cordinate = int((screen_height / 2) - (200 / 2))
        self.master.geometry("{}x{}+{}+{}".format(400, 200, x_cordinate, y_cordinate))

        self.validation_frame = tk.Frame(self.master, padx=10, pady=10)
        self.validation_frame.pack()

        # Ajouter l'étiquette "Password" en haut de la zone de texte
        self.password_label = tk.Label(self.validation_frame, text="Password", fg="indigo", font=("Arial", 14))
        self.password_label.grid(row=0, column=0, pady=5)

        # Centrer la zone de texte
        self.password_entry = ttk.Entry(self.validation_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=0, pady=5)
        self.password_entry.focus()
        self.validation_frame.columnconfigure(0, weight=1)  # Centrer la colonne

        # Centrer les boutons
        self.button_frame = tk.Frame(self.master, padx=10, pady=10)
        self.button_frame.pack()
        self.button_frame.columnconfigure(0, weight=1)  # Centrer la colonne

        self.validate_button = ttk.Button(self.button_frame, text="Valider", command=self.validate_password)
        self.validate_button.grid(row=0, column=0, padx=5)

        self.encrypt_button = ttk.Button(self.button_frame, text="Crypter", command=self.encrypt_password,
                                         state=tk.DISABLED)
        self.encrypt_button.grid(row=0, column=1, padx=5)

        self.message_label = tk.Label(self.master, text="")
        self.message_label.pack(pady=10)

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