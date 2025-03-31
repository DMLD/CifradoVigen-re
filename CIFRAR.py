import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os

class VigenereApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cifrador Vigenère")
        self.root.geometry("600x400")
        
        # Configurar pestañas
        self.notebook = ttk.Notebook(root)
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_tab, text="Cifrar")
        self.notebook.add(self.decrypt_tab, text="Descifrar")
        self.notebook.pack(expand=True, fill="both")
        
        # Configurar pestaña de cifrado 
        self.setup_encrypt_tab()
        
        # Configurar pestaña de descifrado
        self.setup_decrypt_tab()
    
    def setup_encrypt_tab(self):
        # Widgets
        ttk.Label(self.encrypt_tab, text="Mensaje a cifrar:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        # Campo de texto para entrada
        self.text_input = tk.Text(self.encrypt_tab, height=5, width=50)
        self.text_input.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        
        # Clave
        ttk.Label(self.encrypt_tab, text="Clave de cifrado:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.encrypt_key = ttk.Entry(self.encrypt_tab, width=50)
        self.encrypt_key.grid(row=3, column=0, columnspan=2, padx=10, sticky="ew")
        
        # Archivo de salida
        ttk.Label(self.encrypt_tab, text="Guardar como:").grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.output_file = ttk.Entry(self.encrypt_tab, width=50)
        self.output_file.grid(row=5, column=0, padx=10, sticky="ew")
        ttk.Button(self.encrypt_tab, text="Examinar", command=self.browse_output_file).grid(row=5, column=1, padx=10)
        
        # Botón de cifrado
        ttk.Button(self.encrypt_tab, text="Cifrar Mensaje", command=self.encrypt).grid(row=6, column=0, columnspan=2, pady=10)
    
    def setup_decrypt_tab(self):
        # Widgets 
        ttk.Label(self.decrypt_tab, text="Archivo cifrado:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.cipher_file = ttk.Entry(self.decrypt_tab, width=50)
        self.cipher_file.grid(row=1, column=0, padx=10, sticky="ew")
        ttk.Button(self.decrypt_tab, text="Examinar", command=self.browse_cipher_file).grid(row=1, column=1, padx=10)
        
        ttk.Label(self.decrypt_tab, text="Clave de descifrado:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.decrypt_key = ttk.Entry(self.decrypt_tab, width=50)
        self.decrypt_key.grid(row=3, column=0, columnspan=2, padx=10, sticky="ew")
        
        ttk.Button(self.decrypt_tab, text="Descifrar Archivo", command=self.decrypt).grid(row=4, column=0, columnspan=2, pady=10)
    
    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        self.output_file.delete(0, tk.END)
        self.output_file.insert(0, filename)
    
    def browse_cipher_file(self):
        filename = filedialog.askopenfilename()
        self.cipher_file.delete(0, tk.END)
        self.cipher_file.insert(0, filename)
    
    def encrypt(self):
        try:
            # Obtener mensaje solo desde texto
            message = self.text_input.get("1.0", tk.END).strip()
            
            # Validar campos
            key = self.encrypt_key.get()
            if not message:
                raise ValueError("Ingrese un mensaje para cifrar")
            if not any(c.isalpha() for c in key):
                raise ValueError("La clave debe contener al menos una letra")
            
            # Cifrar y guardar
            encrypted = vigenere_encrypt(message, key)
            output_path = self.output_file.get()
            
            if not output_path:
                raise ValueError("Especifique un archivo de salida")
            
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(encrypted)
            
            # Limpiar campos después de cifrar
            self.text_input.delete("1.0", tk.END)
            self.encrypt_key.delete(0, tk.END)
            self.output_file.delete(0, tk.END)
            
            messagebox.showinfo("Éxito", f"Texto cifrado guardado en:\n{output_path}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt(self):
        
        try:
            filepath = self.cipher_file.get()
            if not os.path.exists(filepath):
                raise ValueError("El archivo cifrado no existe")
            
            with open(filepath, "r", encoding="utf-8") as f:
                ciphertext = f.read()
            
            key = self.decrypt_key.get()
            if not any(c.isalpha() for c in key):
                raise ValueError("Clave inválida")
            
            decrypted = vigenere_decrypt(ciphertext, key)
            messagebox.showinfo("Resultado", f"Mensaje descifrado:\n\n{decrypted}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Funciones de cifrado/descifrado
def vigenere_encrypt(message: str, key: str) -> str:
    processed_key = [k.upper() for k in key if k.isalpha()]
    encrypted = []
    key_index = 0
    for c in message:
        if c.isalpha():
            key_char = processed_key[key_index % len(processed_key)]
            key_index += 1
            offset = ord('A') if c.isupper() else ord('a')
            shifted = (ord(c) - offset + (ord(key_char) - ord('A'))) % 26
            encrypted.append(chr(shifted + offset))
        else:
            encrypted.append(c)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    processed_key = [k.upper() for k in key if k.isalpha()]
    decrypted = []
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            key_char = processed_key[key_index % len(processed_key)]
            key_index += 1
            offset = ord('A') if c.isupper() else ord('a')
            shifted = (ord(c) - offset - (ord(key_char) - ord('A'))) % 26
            decrypted.append(chr(shifted + offset))
        else:
            decrypted.append(c)
    return ''.join(decrypted)

if __name__ == "__main__":
    root = tk.Tk()
    app = VigenereApp(root)
    root.mainloop()