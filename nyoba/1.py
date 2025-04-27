import tkinter as tk
from tkinter import ttk

# S-Box + Inverse S-Box
s_box = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]
inv_s_box = [10, 5, 9, 11, 1, 7, 8, 15, 6, 0, 2, 3, 12, 4, 13, 14]

# lookup tables for MixColumns & Inverse MixColumns
mult4 = [0,4,8,12,3,7,11,15,6,2,14,10,5,1,13,9]
mult2 = [0,2,4,6,8,0xA,0xC,0xE,3,1,7,5,0xB,9,0xF,0xD]
mult9 = [
    0x0, 0x9, 0x1, 0x8,
    0x2, 0xB, 0x3, 0xA,
    0x4, 0xD, 0x5, 0xC,
    0x6, 0xF, 0x7, 0xE
]

def text_to_state(text):
    return [
        [(text >> 12) & 0xF, (text >> 8) & 0xF],
        [(text >> 4) & 0xF, text & 0xF]
    ]

def state_to_text(state):
    return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]

def sub_nibbles(state, sbox):
    return [[sbox[state[0][0]], sbox[state[0][1]]], [sbox[state[1][0]], sbox[state[1][1]]]]

def shift_rows(state):
    return [[state[0][0], state[0][1]], [state[1][1], state[1][0]]]

def mix_columns(state):
    new_state = [[0]*2 for _ in range(2)]
    a, c = state[0][0], state[1][0]
    new_state[0][0] = a ^ mult4[c]
    new_state[1][0] = mult4[a] ^ c
    b, d = state[0][1], state[1][1]
    new_state[0][1] = b ^ mult4[d]
    new_state[1][1] = mult4[b] ^ d
    return new_state

def add_round_key(state, key):
    return [[state[0][0] ^ key[0][0], state[0][1] ^ key[0][1]],
            [state[1][0] ^ key[1][0], state[1][1] ^ key[1][1]]]

def key_expansion(key, round_constants=[0x1, 0x2, 0x4]):
    state = text_to_state(key)
    w0, w1, w2, w3 = state[0][0], state[0][1], state[1][0], state[1][1]
    keys = [[[w0, w1], [w2, w3]]]
    for i in range(3):
        rc = round_constants[i]
        temp = s_box[w3] ^ rc
        w4 = w0 ^ temp
        w5 = w1 ^ w4
        w6 = w2 ^ w5
        w7 = w3 ^ w6
        keys.append([[w4, w5], [w6, w7]])
        w0, w1, w2, w3 = w4, w5, w6, w7
    return keys

def encrypt(plaintext, key):
    keys = key_expansion(key)
    state = text_to_state(plaintext)
    state = add_round_key(state, keys[0])
    for i in range(1, 3):
        state = sub_nibbles(state, s_box)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, keys[i])
    state = sub_nibbles(state, s_box)
    state = shift_rows(state)
    state = add_round_key(state, keys[3])
    return state_to_text(state)

def inverse_mix_columns(state):
    new_state = [[0]*2 for _ in range(2)]
    a, c = state[0][0], state[1][0]
    new_state[0][0] = mult9[a] ^ mult2[c]
    new_state[1][0] = mult2[a] ^ mult9[c]
    b, d = state[0][1], state[1][1]
    new_state[0][1] = mult9[b] ^ mult2[d]
    new_state[1][1] = mult2[b] ^ mult9[d]
    return new_state

def decrypt(ciphertext, key):
    keys = key_expansion(key)
    state = text_to_state(ciphertext)
    state = add_round_key(state, keys[3])
    state = shift_rows(state)
    state = sub_nibbles(state, inv_s_box)
    for i in range(2, 0, -1):
        state = add_round_key(state, keys[i])
        state = inverse_mix_columns(state)
        state = shift_rows(state)
        state = sub_nibbles(state, inv_s_box)
    state = add_round_key(state, keys[0])
    return state_to_text(state)

# GUI 
class MiniAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini-AES Encryption/Decryption")
        
        ttk.Label(root, text="Plaintext (16-bit hex):").grid(row=0, column=0, padx=10, pady=5)
        self.plaintext = ttk.Entry(root)
        self.plaintext.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(root, text="Key (16-bit hex):").grid(row=1, column=0, padx=10, pady=5)
        self.key = ttk.Entry(root)
        self.key.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Button(root, text="Encrypt", command=self.encrypt).grid(row=2, column=0, padx=10, pady=5)
        ttk.Button(root, text="Decrypt", command=self.decrypt).grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(root, text="Result:").grid(row=3, column=0, padx=10, pady=5)
        self.result = ttk.Label(root, text="")
        self.result.grid(row=3, column=1, padx=10, pady=5)
    
    def encrypt(self):
        try:
            plaintext = int(self.plaintext.get(), 16)
            key = int(self.key.get(), 16)
            ciphertext = encrypt(plaintext, key)
            self.result.config(text=f"Ciphertext: {ciphertext:04X}")
        except:
            self.result.config(text="Invalid input!")
    
    def decrypt(self):
        try:
            ciphertext = int(self.plaintext.get(), 16)
            key = int(self.key.get(), 16)
            plaintext = decrypt(ciphertext, key)
            self.result.config(text=f"Decrypted: {plaintext:04X}")
        except:
            self.result.config(text="Invalid input!")

if __name__ == "__main__":
    root = tk.Tk()
    app = MiniAESApp(root)
    root.mainloop()
