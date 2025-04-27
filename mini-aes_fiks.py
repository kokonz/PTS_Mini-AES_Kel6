import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

# A.1: Definisi S-Box & Inverse S-Box
# (operasi SubNibbles menggunakan 4-bit lookup)
s_box = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]
inv_s_box = [10, 5, 9, 11, 1, 7, 8, 15, 6, 0, 2, 3, 12, 4, 13, 14]

# A.1: Lookup tables untuk MixColumns & Inverse MixColumns
mult4 = [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9]
mult2 = [0, 2, 4, 6, 8, 0xA, 0xC, 0xE, 3, 1, 7, 5, 0xB, 9, 0xF, 0xD]
# A.1: Dynamic generation mult9 untuk inverse MixColumns
t_mult9 = [(mult2[mult2[mult2[a]]] ^ a) & 0xF for a in range(16)]
mult9 = t_mult9

# Spesifikasi A.1: Konversi antara 16-bit int dan 2x2 nibble state
# A.1: Representasi plaintext dan key 16-bit

def text_to_state(text):
    return [[(text >> 12) & 0xF, (text >> 8) & 0xF],
            [(text >> 4) & 0xF, text & 0xF]]

def state_to_text(state):
    return ((state[0][0] & 0xF) << 12) | ((state[0][1] & 0xF) << 8) | ((state[1][0] & 0xF) << 4) | (state[1][1] & 0xF)

# Spesifikasi A.1: Operasi Mini-AES (SubNibbles, ShiftRows, MixColumns, AddRoundKey)

def sub_nibbles(state, box):
    # A.1.1: SubNibbles
    return [[box[state[0][0]], box[state[0][1]]],
            [box[state[1][0]], box[state[1][1]]]]

def shift_rows(state):
    # A.1.2: ShiftRows
    return [[state[0][0], state[0][1]],
            [state[1][1], state[1][0]]]

def mix_columns(state):
    # A.1.3: MixColumns
    a, c = state[0][0], state[1][0]
    b, d = state[0][1], state[1][1]
    return [[(a ^ mult4[c]) & 0xF, (b ^ mult4[d]) & 0xF],
            [(mult4[a] ^ c) & 0xF, (mult4[b] ^ d) & 0xF]]

def inverse_mix_columns(state):
    # A.1.4: Inverse MixColumns
    a, c = state[0][0], state[1][0]
    b, d = state[0][1], state[1][1]
    return [[(mult9[a] ^ mult2[c]) & 0xF, (mult9[b] ^ mult2[d]) & 0xF],
            [(mult2[a] ^ mult9[c]) & 0xF, (mult2[b] ^ mult9[d]) & 0xF]]

def add_round_key(state, key):
    # A.1.5: AddRoundKey
    return [[state[0][0] ^ key[0][0], state[0][1] ^ key[0][1]],
            [state[1][0] ^ key[1][0], state[1][1] ^ key[1][1]]]

# Spesifikasi A.2: Key Expansion (Round Key Generator)

def key_expansion(key, rcon=[0x1, 0x2, 0x4]):
    # A.2.1: Ambil key awal 16-bit
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

# Utility
def format_hex(val):
    return f"{val:04X}"

# Spesifikasi A.3: Enkripsi/Dekripsi dengan logging (log tiap ronde ditampilkan di GUI)

def encrypt_verbose(pt, key, log):
    # A.3.1: Encrypt (3 ronde + final) dengan Sub/Shift/Mix/Add
    keys = key_expansion(key)
    state = text_to_state(pt)
    log(f"Initial: {format_hex(pt)}")
    # A.3.2: AddRoundKey awal
    state = add_round_key(state, keys[0])
    log(f"AddRoundKey 0 -> {format_hex(state_to_text(state))}")
    for r in range(1, 3):
        log("\n")
        log(f"-- Round {r} --")
        state = sub_nibbles(state, s_box);
        log(f"SubNibbles -> {format_hex(state_to_text(state))}")
        state = shift_rows(state);
        log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
        state = mix_columns(state);
        log(f"MixColumns-> {format_hex(state_to_text(state))}")
        state = add_round_key(state, keys[r]);
        log(f"AddRoundKey {r} -> {format_hex(state_to_text(state))}")
    log("\n")
    log("-- Final Round --")
    state = sub_nibbles(state, s_box);
    log(f"SubNibbles -> {format_hex(state_to_text(state))}")
    state = shift_rows(state);
    log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
    state = add_round_key(state, keys[3]);
    ct = state_to_text(state)
    log("\n")
    log(f"Ciphertext: {format_hex(ct)}")
    log("\n")
    return ct


def decrypt_verbose(ct, key, log):
    # B.1: Decrypt (inverse sekuens) dengan log per ronde
    keys = key_expansion(key)
    state = text_to_state(ct)
    log(f"Initial: {format_hex(ct)}")
    state = add_round_key(state, keys[3]); log(f"AddRoundKey 3 -> {format_hex(state_to_text(state))}")
    state = shift_rows(state); log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
    state = sub_nibbles(state, inv_s_box); log(f"SubNibbles -> {format_hex(state_to_text(state))}")
    for r in range(2, 0, -1):
        log("\n")
        log(f"-- Round {r} --")
        state = add_round_key(state, keys[r]);   log(f"AddRoundKey {r} -> {format_hex(state_to_text(state))}")
        state = inverse_mix_columns(state);      log(f"InvMixCol  -> {format_hex(state_to_text(state))}")
        state = shift_rows(state);               log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
        state = sub_nibbles(state, inv_s_box);   log(f"SubNibbles -> {format_hex(state_to_text(state))}")
    state = add_round_key(state, keys[0]); pt = state_to_text(state)
    log("\n")
    log(f"Plaintext: {format_hex(pt)}")
    return pt

# Spesifikasi A.3.3: Minimal 3 test case dengan expected output benar
# (pt, key, expected_cipher)
test_cases = [
    (0x1234, 0xABCD, 0x18C2),  # sample ABCD 1234
    (0x0000, 0x0000, 0xB0C7),  # all-zero
    (0xFFFF, 0x0000, 0x06AC),  # all-one plaintext, zero key
    (0xAAAA, 0x5555, 0xA63E),  # pola bergantian
    (0x0F0F, 0xF0F0, 0x2A86)   # pola nibble
]

def run_tests(log, result_label):
    # A.3.3: Fungsi menjalankan test case otomatis
    log("Menjalankan 5 test case...")
    all_pass = True
    for i, (pt, key, exp_ct) in enumerate(test_cases, 1):
        ct = encrypt_verbose(pt, key, log)
        pt2 = decrypt_verbose(ct, key, log)
        ok_enc = (ct == exp_ct)
        ok_dec = (pt2 == pt)
        status = "PASS" if (ok_enc and ok_dec) else "FAIL"
        log(f"Test {i}: PT={format_hex(pt)} Key={format_hex(key)} -> CT={format_hex(ct)} " +
            f"(exp {format_hex(exp_ct)}) Decrypted={format_hex(pt2)} [{status}]\n")
        if not (ok_enc and ok_dec): all_pass = False
    result_label.config(text=f"Tests {'PASSED' if all_pass else 'SOME FAILED'}")

def count_changed_bits(x, y):
    """Menghitung jumlah bit berbeda antara dua 16-bit angka."""
    return bin(x ^ y).count('1')

def avalanche_test(pt, key, log):
    """Avalanche Effect Test: Ubah 1 bit di PT dan Key, log perubahan."""
    original_ct = encrypt_verbose(pt, key, lambda msg: None)
    log("=== Avalanche Test: Perubahan 1 bit di Plaintext ===")
    for i in range(16):
        flipped_pt = pt ^ (1 << i)
        new_ct = encrypt_verbose(flipped_pt, key, lambda msg: None)
        changed_bits = count_changed_bits(original_ct, new_ct)
        percentage = (changed_bits / 16) * 100
        log(f"Bit {i}: PT={format_hex(flipped_pt)}, CT={format_hex(new_ct)}, "
            f"Changed Bits={changed_bits}/16 ({percentage:.2f}%)")

    log("\n=== Avalanche Test: Perubahan 1 bit di Key ===")
    for i in range(16):
        flipped_key = key ^ (1 << i)
        new_ct = encrypt_verbose(pt, flipped_key, lambda msg: None)
        changed_bits = count_changed_bits(original_ct, new_ct)
        percentage = (changed_bits / 16) * 100
        log(f"Bit {i}: Key={format_hex(flipped_key)}, CT={format_hex(new_ct)}, "
            f"Changed Bits={changed_bits}/16 ({percentage:.2f}%)")

# Spesifikasi A.3: GUI dengan Tkinter untuk input, output, log, dan test
class MiniAESApp:
    def __init__(self, root):
        root.title("Mini-AES Encryption/Decryption")
        # Input field untuk plaintext & key (A.3.1)
        ttk.Label(root, text="Plaintext (hex 4-digit):").grid(row=0, column=0, sticky="w")
        self.plain_entry = ttk.Entry(root, width=6); self.plain_entry.grid(row=0, column=1)
        ttk.Label(root, text="Key (hex 4-digit):").grid(row=1, column=0, sticky="w")
        self.key_entry = ttk.Entry(root, width=6); self.key_entry.grid(row=1, column=1)
        # Tombol Enkripsi, Dekripsi, dan Run Tests
        ttk.Button(root, text="Enkripsi", command=self.do_encrypt).grid(row=2, column=0)
        ttk.Button(root, text="Dekripsi", command=self.do_decrypt).grid(row=2, column=1)
        ttk.Button(root, text="Run Tests", command=self.do_tests).grid(row=2, column=2)
        ttk.Button(root, text="Avalanche Test", command=self.do_avalance).grid(row=2, column=3)
        # Label hasil (A.3.2)
        self.result_label = ttk.Label(root, text="----"); self.result_label.grid(row=3, column=0, columnspan=3)
        # ScrolledText untuk log detail tiap ronde (A.3.2)
        self.log = ScrolledText(root, width=60, height=15, state="disabled");
        self.log.grid(row=4, column=0, columnspan=3, pady=5)

    def append_log(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def do_encrypt(self):
        # A.3.1: Jalankan enkripsi dan tampilkan log
        self.clear_log()
        try:
            pt = int(self.plain_entry.get(), 16); key = int(self.key_entry.get(), 16)
            ct = encrypt_verbose(pt, key, self.append_log)
            self.result_label.config(text=f"Ciphertext: {format_hex(ct)}")
        except ValueError:
            self.result_label.config(text="Input hex tidak valid!")

    def do_decrypt(self):
        # A.3.1: Jalankan dekripsi dan tampilkan log
        self.clear_log()
        try:
            ct = int(self.plain_entry.get(), 16); key = int(self.key_entry.get(), 16)
            pt = decrypt_verbose(ct, key, self.append_log)
            self.result_label.config(text=f"Plaintext: {format_hex(pt)}")
        except ValueError:
            self.result_label.config(text="Input hex tidak valid!")

    def do_tests(self):
        # A.3.3: Jalankan 5 test case otomatis
        self.clear_log()
        run_tests(self.append_log, self.result_label)
        
    def do_avalance(self):
        self.clear_log()
        try:
            pt = int(self.plain_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            avalanche_test(pt, key, self.append_log)
            self.result_label.config(text="Avalanche test completed")
        except ValueError:
            self.result_label.config(text="Input hex tidak valid!")

# Main program (A.3: GUI)
if __name__ == '__main__':
    root = tk.Tk()
    MiniAESApp(root)
    root.mainloop()
