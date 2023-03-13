import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re
import hashlib
import random
import string


class PasswordValidatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Validation et cryptage de mot de passe")
        self.master.geometry("400x400")

        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (400 / 2))
        y_cordinate = int((screen_height / 2) - (400 / 2))
        self.master.geometry("{}x{}+{}+{}".format(400, 400, x_cordinate, y_cordinate))

        self.validation_frame = tk.Frame(self.master, padx=10, pady=10)
        self.validation_frame.pack()

        self.password_label = tk.Label(self.validation_frame, text="Password", fg="indigo", font=("Arial", 14))
        self.password_label.grid(row=0, column=0, pady=5)

        self.password_entry = ttk.Entry(self.validation_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=0, pady=5)
        self.password_entry.focus()
        self.validation_frame.columnconfigure(0, weight=1)

        self.strength_label = tk.Label(self.master, text="Force du mot de passe : ", font=("Arial", 12))
        self.strength_label.pack(pady=10)

        self.button_frame = tk.Frame(self.master, padx=10, pady=10)
        self.button_frame.pack()
        self.button_frame.columnconfigure(0, weight=1)

        self.validate_button = ttk.Button(self.button_frame, text="Valider", command=self.validate_password,
                                          cursor="hand2", style="TButton.Validate.TButton")
        self.validate_button.grid(row=0, column=0, padx=5)

        self.encrypt_button = ttk.Button(self.button_frame, text="Crypter", command=self.encrypt_password,
                                         cursor="hand2", state=tk.DISABLED, style="TButton.Encrypt.TButton")
        self.encrypt_button.grid(row=0, column=1, padx=5)

        self.generate_button = ttk.Button(self.button_frame, text="Générer", command=self.generate_password,
                                          cursor="hand2", style="TButton.Generate.TButton")
        self.generate_button.grid(row=1, column=0, padx=5)

        self.check_strength_button = ttk.Button(self.button_frame, text="Vérifier la force",
                                                command=self.check_password_strength, cursor="hand2",
                                                style="TButton.CheckStrength.TButton")
        self.check_strength_button.grid(row=1, column=1, padx=5)

        self.tips_button = ttk.Button(self.button_frame, text="Astuces", command=self.show_password_tips,
                                      cursor="hand2", style="TButton.Tips.TButton")
        self.tips_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Styles de boutons personnalisés
        self.master.style = ttk.Style()
        self.master.style.theme_use("clam")

        self.master.style.configure("TButton.Validate.TButton", foreground="white", background="green",
                                    font=("Arial", 12), padding=8, borderwidth=0)
        self.master.style.map("TButton.Validate.TButton", foreground=[("active", "white"), ("disabled", "gray")],
                              background=[("active", "darkgreen"), ("disabled", "lightgray")])
        self.master.style.configure("TButton.Encrypt.TButton", foreground="white", background="blue",
                                    font=("Arial", 12), padding=8, borderwidth=0)
        self.master.style.map("TButton.Encrypt.TButton", foreground=[("active", "white"), ("disabled", "gray")],
                              background=[("active", "darkblue"), ("disabled", "lightgray")])

        self.master.style.configure("TButton.Generate.TButton", foreground="white", background="orange",
                                    font=("Arial", 12), padding=8, borderwidth=0)
        self.master.style.map("TButton.Generate.TButton", foreground=[("active", "white"), ("disabled", "gray")],
                              background=[("active", "darkorange"), ("disabled", "lightgray")])

        self.master.style.configure("TButton.CheckStrength.TButton", foreground="white", background="purple",
                                    font=("Arial", 12), padding=8, borderwidth=0)
        self.master.style.map("TButton.CheckStrength.TButton", foreground=[("active", "white"), ("disabled", "gray")],
                              background=[("active", "darkpurple"), ("disabled", "lightgray")])

        self.master.style.configure("TButton.Tips.TButton", foreground="white", background="gray", font=("Arial", 12),
                                    padding=8, borderwidth=0)
        self.master.style.map("TButton.Tips.TButton", foreground=[("active", "white")],
                              background=[("active", "black")])

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

    def generate_password(self):
        password_length = 12  # longueur du mot de passe généré
        while True:
            password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in
                               range(password_length))
            errors = self.validate_password_rules(password)
            if not errors:
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password)
                break

    def check_password_strength(self):
        password = self.password_entry.get()
        strength = 0
        if len(password) >= 8:
            strength += 1
        if re.search("[a-z]", password):
            strength += 1
        if re.search("[A-Z]", password):
            strength += 1
        if re.search("[0-9]", password):
            strength += 1
        if re.search("[!@#$%^&*()_+-={};':\"|,.<>?~`]", password):
            strength += 1

        if strength == 0:
            strength_text = "Très faible"
        elif strength == 1:
            strength_text = "Faible"
        elif strength == 2:
            strength_text = "Moyenne"
        elif strength == 3:
            strength_text = "Bonne"
        elif strength == 4:
            strength_text = "Très bonne"
        else:
            strength_text = "Excellente"

        self.strength_label.config(text="Force du mot de passe : {}".format(strength_text))

    def show_password_tips(self):
        tips = [
            "Utilisez au moins 8 caractères.",
            "Utilisez une combinaison de lettres majuscules et minuscules.",
            "Utilisez des chiffres et des caractères spéciaux.",
            "N'utilisez pas de mots courants ou de séquences de chiffres.",
            "Changez régulièrement de mot de passe."
        ]
        tip_message = "\n\n".join(tips)
        tk.messagebox.showinfo("Astuces pour créer un mot de passe fort", tip_message)

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordValidatorGUI(root)
    root.mainloop()