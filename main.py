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

        # Positionne la fenêtre au centre de l'écran
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (400 / 2))
        y_cordinate = int((screen_height / 2) - (400 / 2))
        self.master.geometry("{}x{}+{}+{}".format(400, 400, x_cordinate, y_cordinate))

        # Crée un cadre pour l'entrée du mot de passe et les étiquettes associées
        self.validation_frame = tk.Frame(self.master, padx=10, pady=10)
        self.validation_frame.pack()

        self.password_label = tk.Label(self.validation_frame, text="Password", fg="indigo", font=("Arial", 20))
        self.password_label.grid(row=0, column=0, pady=5)

        # Modifie la valeur de "width" pour augmenter la taille du champ de texte du mot de passe
        self.password_entry = ttk.Entry(self.validation_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=0, pady=5)
        self.password_entry.focus()

        # Affiche l'étiquette de force du mot de passe
        self.strength_label = tk.Label(self.master, text="Force du mot de passe : ", font=("Arial", 12))
        self.strength_label.pack(pady=10)

        # Crée un cadre pour les boutons de validation, de cryptage, de génération, de vérification de force et d'astuces
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
        self.generate_button.grid(row=1, column=0, padx=5, pady=20)

        self.check_strength_button = ttk.Button(self.button_frame, text="Vérifier la force",
                                                command=self.check_password_strength, cursor="hand2",
                                                style="TButton.CheckStrength.TButton")
        self.check_strength_button.grid(row=1, column=1, padx=5, pady=20)

        self.tips_button = ttk.Button(self.button_frame, text="Astuces", command=self.show_password_tips,
                                      cursor="hand2", style="TButton.Tips.TButton")
        self.tips_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Configure les styles personnalisés des boutons
        self.master.style = ttk.Style()
        self.master.style.theme_use("clam")

        self.master.style.configure("TButton.Validate.TButton", foreground="white",background="green", font=("Arial", 12), padding=8, borderwidth=0)
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
                          background=[("active", "pink"), ("disabled", "lightgray")])

        self.master.style.configure("TButton.Tips.TButton", foreground="white", background="gray", font=("Arial", 12),
                                padding=8, borderwidth=0)
        self.master.style.map("TButton.Tips.TButton", foreground=[("active", "white")],
                          background=[("active", "black")])

        # Affiche les messages d'erreur/succès
        self.message_label = tk.Label(self.master, text="")
        self.message_label.pack(pady=10)

    def validate_password(self):
        # Récupère le mot de passe de l'entrée
        password = self.password_entry.get()

        # Valide le mot de passe selon les règles
        errors = self.validate_password_rules(password)

        if errors:
            # Si des erreurs sont retournées, affiche un message d'erreur
            error_message = "Le mot de passe n'est pas valide : \n\n{}".format("\n".join(errors))
            messagebox.showerror("Erreur", error_message)
        else:
            # Si le mot de passe est valide, active le bouton "Crypter"
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
        # Récupère le mot de passe de l'entrée
        password = self.password_entry.get()

        # Sel fixe utilisé pour saler le mot de passe
        salt = "mysalt"

        # Ajoute le sel au mot de passe
        salted_password = password + salt

        # Génère le hash SHA-256 du mot de passe salé
        hashed_password = hashlib.sha256(salted_password.encode())

        # Convertit le hash en chaîne hexadécimale
        encrypted_password = hashed_password.hexdigest()

        # Affiche un message de succès avec le mot de passe crypté
        messagebox.showinfo("Succès", "Le mot de passe a été crypté avec succès : " + encrypted_password)

        # le salage consiste à ajouter une valeur aléatoire au mot de passe avant de le hacher, ce qui rend plus
        # difficile la tâche des attaquants qui cherchent à décrypter les mots de passe.

    def generate_password(self):
        # Longueur du mot de passe généré
        password_length = 12

        while True:
            # Génère une chaîne aléatoire contenant des lettres, des chiffres et des caractères spéciaux
            password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in
                               range(password_length))

            # Valide le mot de passe généré selon les règles
            errors = self.validate_password_rules(password)

            if not errors:
                # Si le mot de passe généré est valide, l'affiche dans l'entrée de mot de passe et sort de la boucle
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password)
                break

    def check_password_strength(self):
        # Récupère le mot de passe de l'entrée
        password = self.password_entry.get()

        # Initialise la force du mot de passe à 0
        strength = 0

        # Vérifie si le mot de passe satisfait chaque règle de complexité et incrémente la force si c'est le cas
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

        # Détermine le niveau de force du mot de passe en fonction de la force calculée
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

        # Affiche le niveau de force du mot de passe dans l'étiquette de force
        self.strength_label.config(text="Force du mot de passe : {}".format(strength_text))

    def show_password_tips(self):
        # Liste des astuces pour créer un mot de passe fort
        tips = [
            "Utilisez au moins 8 caractères.",
            "Utilisez une combinaison de lettres majuscules et minuscules.",
            "Utilisez des chiffres et des caractères spéciaux.",
            "N'utilisez pas de mots courants ou de séquences de chiffres.",
            "Changez régulièrement de mot de passe."
        ]

        # Crée une chaîne avec toutes les astuces, séparées par des sauts de ligne
        tip_message = "\n\n".join(tips)

        # Crée une nouvelle fenêtre pour afficher les astuces
        tips_window = tk.Toplevel(self.master)
        tips_window.title("Astuces pour créer un mot de passe fort")
        tips_window.geometry("400x400")

        # Centre la fenêtre des astuces sur l'écran
        screen_width = tips_window.winfo_screenwidth()
        screen_height = tips_window.winfo_screenheight()
        x_cordinate = int((screen_width / 2) - (400 / 2))
        y_cordinate = int((screen_height / 2) - (400 / 2))
        tips_window.geometry("{}x{}+{}+{}".format(400, 400, x_cordinate, y_cordinate))

        # Crée un widget Text pour afficher le message des astuces et l'ajoute à la fenêtre des astuces
        tips_text = tk.Text(tips_window, font=("Arial", 12), padx=20, pady=20, wrap=tk.WORD, relief=tk.FLAT,
                            bg=tips_window.cget("bg"))
        tips_text.insert(tk.END, tip_message)
        tips_text.grid(row=0, column=0, sticky="nsew")  # Utilise grid() au lieu de pack()
        tips_text.config(state=tk.DISABLED)  # Empêche la modification du texte

        # Crée un bouton "OK" pour fermer la fenêtre des astuces et l'ajoute à la fenêtre des astuces
        ok_button = ttk.Button(tips_window, text="OK", command=tips_window.destroy)
        ok_button.grid(row=1, column=0, pady=20)  # Utilise grid() au lieu de pack()

        # Configure le poids des lignes et des colonnes pour la mise en page
        tips_window.grid_rowconfigure(0, weight=1)
        tips_window.grid_columnconfigure(0, weight=1)


if __name__ == '__main__':
    # Si le module est exécuté en tant que programme principal, crée une instance de la classe PasswordValidatorGUI
    # et exécute la boucle principale de l'interface utilisateur.
    root = tk.Tk()
    app = PasswordValidatorGUI(root)
    root.mainloop()
