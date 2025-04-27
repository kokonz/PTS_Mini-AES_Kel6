import tkinter as tk
from tkinter import ttk

# S-Box + Inverse S-Box
s_box = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]
inv_s_box = [10, 5, 9, 11, 1, 7, 8, 15, 6, 0, 2, 3, 12, 4, 13, 14]

# lookup tables for MixColumns & Inverse MixColumns
mult4 = [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9]
mult2 = [0, 2, 4, 6, 8, 0xA, 0xC, 0xE, 3, 1, 7, 5, 0xB, 9, 0xF, 0xD]
# Corrected mult9 for GF(2^4) inverse of 4-multiplier
elements = []
# compute mult8 then ^ a to get mult9 dynamically
for a in range(16):
    # mult2 twice = mult4, thrice = mult8
    m4 = mult2[mult2[a]]
    m8 = mult2[m4]
    elements.append((m8 ^ a) & 0xF)
mult9 = elements

# Convert between 16-bit int and 2x2 nibble state
def text_to_state(text):
    return [
        [(text >> 12) & 0xF, (text >> 8) & 0xF],
        [(text >> 4) & 0xF, text & 0xF]
    ]

def state_to_text(state):
    return ((state[0][0] & 0xF) << 12) | ((state[0][1] & 0xF) << 8) | ((state[1][0] & 0xF) << 4) | (state[1][1] & 0xF)

# Core Mini-AES operations
def sub_nibbles(state, box):
    return [
        [box[state[0][0]], box[state[0][1]]],
        [box[state[1][0]], box[state[1][1]]]
    ]

def shift_rows(state):
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ]

def mix_columns(state):
    a, c = state[0][0], state[1][0]
    b, d = state[0][1], state[1][1]
    return [
        [(a ^ mult4[c]) & 0xF, (b ^ mult4[d]) & 0xF],
        [(mult4[a] ^ c) & 0xF, (mult4[b] ^ d) & 0xF]
    ]

def inverse_mix_columns(state):
    a, c = state[0][0], state[1][0]
    b, d = state[0][1], state[1][1]
    return [
        [(mult9[a] ^ mult2[c]) & 0xF, (mult9[b] ^ mult2[d]) & 0xF],
        [(mult2[a] ^ mult9[c]) & 0xF, (mult2[b] ^ mult9[d]) & 0xF]
    ]

def add_round_key(state, key):
    return [
        [state[0][0] ^ key[0][0], state[0][1] ^ key[0][1]],
        [state[1][0] ^ key[1][0], state[1][1] ^ key[1][1]]
    ]

# Key expansion (4 round keys)
def key_expansion(key, rcon=[0x1, 0x2, 0x4]):
    w = text_to_state(key)
    w0, w1, w2, w3 = w[0][0], w[0][1], w[1][0], w[1][1]
    round_keys = [[[w0, w1], [w2, w3]]]
    for i in range(3):
        temp = s_box[w3] ^ rcon[i]
        w4 = w0 ^ temp
        w5 = w1 ^ w4
        w6 = w2 ^ w5
        w7 = w3 ^ w6
        round_keys.append([[w4, w5], [w6, w7]])
        w0, w1, w2, w3 = w4, w5, w6, w7
    return round_keys

# Encryption and Decryption

def encrypt(pt, key):
    keys = key_expansion(key)
    state = text_to_state(pt)
    state = add_round_key(state, keys[0])
    for r in range(1, 3):
        state = sub_nibbles(state, s_box)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, keys[r])
    state = sub_nibbles(state, s_box)
    state = shift_rows(state)
    state = add_round_key(state, keys[3])
    return state_to_text(state)

def decrypt(ct, key):
    keys = key_expansion(key)
    state = text_to_state(ct)
    state = add_round_key(state, keys[3])
    state = shift_rows(state)
    state = sub_nibbles(state, inv_s_box)
    for r in range(2, 0, -1):
        state = add_round_key(state, keys[r])
        state = inverse_mix_columns(state)
        state = shift_rows(state)
        state = sub_nibbles(state, inv_s_box)
    state = add_round_key(state, keys[0])
    return state_to_text(state)

# GUI
def format_hex(val):
    return f"{val:04X}"

class MiniAESApp:
    def __init__(self, root):
        self.root = root
        root.title("Mini-AES (Fixed)")

        ttk.Label(root, text="Plaintext (hex 4-digit):").grid(row=0, column=0)
        self.plain = ttk.Entry(root)
        self.plain.grid(row=0, column=1)

        ttk.Label(root, text="Key (hex 4-digit):").grid(row=1, column=0)
        self.key = ttk.Entry(root)
        self.key.grid(row=1, column=1)

        ttk.Button(root, text="Encrypt", command=self.do_encrypt).grid(row=2, column=0)
        ttk.Button(root, text="Decrypt", command=self.do_decrypt).grid(row=2, column=1)

        ttk.Label(root, text="Result:").grid(row=3, column=0)
        self.res = ttk.Label(root, text="----")
        self.res.grid(row=3, column=1)

    def do_encrypt(self):
        try:
            pt = int(self.plain.get(), 16)
            k  = int(self.key.get(), 16)
            ct = encrypt(pt, k)
            self.res.config(text=f"Ciphertext: {format_hex(ct)}")
        except ValueError:
            self.res.config(text="Invalid hex input!")

    def do_decrypt(self):
        try:
            ct = int(self.plain.get(), 16)
            k  = int(self.key.get(), 16)
            pt = decrypt(ct, k)
            self.res.config(text=f"Decrypted: {format_hex(pt)}")
        except ValueError:
            self.res.config(text="Invalid hex input!")

if __name__ == '__main__':
    root = tk.Tk()
    MiniAESApp(root)
    root.mainloop()
