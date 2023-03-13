import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re
import hashlib


class PasswordValidatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Validation et cryptage de mot de passe")
        self.master.geometry("400x200")

        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (400 / 2))
        y_cordinate = int((screen_height / 2) - (200 / 2))
        self.master.geometry("{}x{}+{}+{}".format(400, 200, x_cordinate, y_cordinate))

        self.validation_frame = tk.Frame(self.master, padx=10, pady=10)
        self.validation_frame.pack()

        self.password_label = tk.Label(self.validation_frame, text="Password", fg="indigo", font=("Arial", 14))
        self.password_label.grid(row=0, column=0, pady=5)

        self.password_entry = ttk.Entry(self.validation_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=0, pady=5)
        self.password_entry.focus()
        self.validation_frame.columnconfigure(0, weight=1)

        self.button_frame = tk.Frame(self.master, padx=10, pady=10)
        self.button_frame.pack()
        self.button_frame.columnconfigure(0, weight=1)

        self.validate_button = ttk.Button(self.button_frame, text="Valider", command=self.validate_password)
        self.validate_button.grid(row=0, column=0, padx=5)

        self.encrypt_button = ttk.Button(self.button_frame, text="Crypter", command=self.encrypt_password,
                                         state=tk.DISABLED)
        self.encrypt_button.grid(row=0, column=1, padx=5)

        self.message_label = tk.Label(self.master, text="")
        self.message_label.pack(pady=10)

    def validate_password(self):
        password = self.password_entry.get()
        errors = self.validate_password_rules(password)  # Valide le mot de passe selon les règles
        if errors:  # Si des erreurs sont retournées, affiche un message d'erreur
            error_message = "Le mot de passe n'est pas valide : \n\n{}".format("\n".join(errors))
            messagebox.showerror("Erreur", error_message)
        else:  # Si le mot de passe est valide, active le bouton "Crypter"
            messagebox.showinfo("Succès", "Le mot de passe est valide.")
            self.encrypt_button.config(state=tk.NORMAL)

    def validate_password_rules(self, password):
        errors = []
        if len(password) < 8:
            errors.append("Le mot de passe doit contenir au moins 8 caractères.")
        if not re.search("[a-z]", password):
            errors.append("Le mot de passe doit contenir au moins une lettre minuscule.")
        if not re.search("[A-Z]", password):
            errors.append("Le mot de passe doit contenir au moins une lettre majuscule.")
        if not re.search("[0-9]", password):
            errors.append("Le mot de passe doit contenir au moins un chiffre.")
        if not re.search("[!@#$%^&*()_+-={};':\"|,.<>?~`]", password):
            errors.append("Le mot de passe doit contenir au moins un caractère spécial.")
        return errors

    def encrypt_password(self):
        password = self.password_entry
        password = self.password_entry.get()
        salt = "mysalt"  # Sel fixe utilisé pour saler le mot de passe
        salted_password = password + salt  # Ajoute le sel au mot de passe
        hashed_password = hashlib.sha256(salted_password.encode())  # Génère le hash SHA-256 du mot de passe salé
        encrypted_password = hashed_password.hexdigest()  # Convertit le hash en chaîne hexadécimale
        messagebox.showinfo("Succès", "Le mot de passe a été crypté avec succès : " + encrypted_password)
        # le salage consiste à ajouter une valeur aléatoire au mot de passe avant de le hacher, ce qui rend plus
        # difficile la tâche des attaquants qui cherchent à décrypter les mots de passe.

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordValidatorGUI(root)
    root.mainloop()