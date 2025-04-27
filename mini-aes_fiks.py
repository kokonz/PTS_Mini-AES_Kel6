import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.scrolledtext import ScrolledText
import os
import csv
import random
import binascii

# Definition of S-Box & Inverse S-Box for SubNibbles operation (4-bit lookup)
s_box = [9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]
inv_s_box = [10, 5, 9, 11, 1, 7, 8, 15, 6, 0, 2, 3, 12, 4, 13, 14]

# Lookup tables for MixColumns & Inverse MixColumns
mult2 = [0, 2, 4, 6, 8, 0xA, 0xC, 0xE, 3, 1, 7, 5, 0xB, 9, 0xF, 0xD]
mult4 = [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9]
# Dynamic generation mult9 for inverse MixColumns
t_mult9 = [(mult2[mult2[mult2[a]]] ^ a) & 0xF for a in range(16)]
mult9 = t_mult9

# Conversion between 16-bit int and 2x2 nibble state matrix
def text_to_state(text):
    return [[(text >> 12) & 0xF, (text >> 8) & 0xF],
            [(text >> 4) & 0xF, text & 0xF]]

def state_to_text(state):
    return ((state[0][0] & 0xF) << 12) | ((state[0][1] & 0xF) << 8) | ((state[1][0] & 0xF) << 4) | (state[1][1] & 0xF)

# Mini-AES Operations:

# SubNibbles: Substitute each nibble using the S-box
def sub_nibbles(state, box):
    return [[box[state[0][0]], box[state[0][1]]],
            [box[state[1][0]], box[state[1][1]]]]

# ShiftRows: Swap the nibbles in the second row
def shift_rows(state):
    return [[state[0][0], state[0][1]],
            [state[1][1], state[1][0]]] # ini merupakan self inverse shift row

# MixColumns: Matrix multiplication in GF(2^4)
def mix_columns(state):
    a, b = state[0][0], state[0][1]
    c, d = state[1][0], state[1][1]
    return [[(a ^ mult4[c]) & 0xF, (b ^ mult4[d]) & 0xF],
            [(mult4[a] ^ c) & 0xF, (mult4[b] ^ d) & 0xF]]

# Inverse MixColumns for decryption
def inverse_mix_columns(state):
    a, b = state[0][0], state[0][1]
    c, d = state[1][0], state[1][1]
    return [[(mult9[a] ^ mult2[c]) & 0xF, (mult9[b] ^ mult2[d]) & 0xF],
            [(mult2[a] ^ mult9[c]) & 0xF, (mult2[b] ^ mult9[d]) & 0xF]]

# AddRoundKey: XOR the state with the round key
def add_round_key(state, key):
    return [[state[0][0] ^ key[0][0], state[0][1] ^ key[0][1]],
            [state[1][0] ^ key[1][0], state[1][1] ^ key[1][1]]]

# Key Expansion (generates round keys)
def key_expansion(key, rcon=[0x1, 0x2, 0x4]):
    # Extract initial 16-bit key
    w = text_to_state(key)
    w0, w1, w2, w3 = w[0][0], w[0][1], w[1][0], w[1][1]
    round_keys = [[[w0, w1], [w2, w3]]]
    
    # Generate the three round keys
    for i in range(3):
        temp = s_box[w3] ^ rcon[i]
        w4 = w0 ^ temp
        w5 = w1 ^ w4
        w6 = w2 ^ w5
        w7 = w3 ^ w6
        round_keys.append([[w4, w5], [w6, w7]])
        w0, w1, w2, w3 = w4, w5, w6, w7
    return round_keys

# Utility function for formatting hex values
def format_hex(val):
    return f"{val:04X}"

# Encryption algorithm with verbose logging
def encrypt_verbose(pt, key, log):
    keys = key_expansion(key)
    state = text_to_state(pt)
    log(f"Initial plaintext: {format_hex(pt)}")
    
    # Initial AddRoundKey
    state = add_round_key(state, keys[0])
    log(f"AddRoundKey 0 -> {format_hex(state_to_text(state))}")
    
    # Two rounds of Sub/Shift/Mix/Add
    for r in range(1, 3):
        log(f"-- Round {r} --")
        state = sub_nibbles(state, s_box)
        log(f"SubNibbles -> {format_hex(state_to_text(state))}")
        state = shift_rows(state)
        log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
        state = mix_columns(state)
        log(f"MixColumns -> {format_hex(state_to_text(state))}")
        state = add_round_key(state, keys[r])
        log(f"AddRoundKey {r} -> {format_hex(state_to_text(state))}")
    
    # Final round (no MixColumns)
    log("-- Final Round --")
    state = sub_nibbles(state, s_box)
    log(f"SubNibbles -> {format_hex(state_to_text(state))}")
    state = shift_rows(state)
    log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
    state = add_round_key(state, keys[3])
    ct = state_to_text(state)
    log(f"Final ciphertext: {format_hex(ct)}")
    return ct

# Decryption algorithm with verbose logging
def decrypt_verbose(ct, key, log):
    keys = key_expansion(key)
    state = text_to_state(ct)
    log(f"Initial ciphertext: {format_hex(ct)}")
    
    # Initial AddRoundKey, ShiftRows, SubNibbles (in reverse order)
    state = add_round_key(state, keys[3])
    log(f"AddRoundKey 3 -> {format_hex(state_to_text(state))}")
    state = shift_rows(state)
    log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
    state = sub_nibbles(state, inv_s_box)
    log(f"InvSubNibbles -> {format_hex(state_to_text(state))}")
    
    # Two rounds of Add/InvMix/Shift/Sub (in reverse order)
    for r in range(2, 0, -1):
        log(f"-- Round {r} --")
        state = add_round_key(state, keys[r])
        log(f"AddRoundKey {r} -> {format_hex(state_to_text(state))}")
        state = inverse_mix_columns(state)
        log(f"InvMixColumns -> {format_hex(state_to_text(state))}")
        state = shift_rows(state)
        log(f"ShiftRows  -> {format_hex(state_to_text(state))}")
        state = sub_nibbles(state, inv_s_box)
        log(f"InvSubNibbles -> {format_hex(state_to_text(state))}")
    
    # Final AddRoundKey
    state = add_round_key(state, keys[0])
    pt = state_to_text(state)
    log(f"Final plaintext: {format_hex(pt)}")
    return pt

# Test cases (plaintext, key, expected_ciphertext)
test_cases = [
    (0x1234, 0xABCD, 0x18C2),  # Sample case
    (0x0000, 0x0000, 0xB0C7),  # All-zero case
    (0xFFFF, 0x0000, 0x06AC),  # All-one plaintext, zero key
    (0xAAAA, 0x5555, 0xA63E),  # Alternating pattern
    (0x0F0F, 0xF0F0, 0x2A86)   # Nibble pattern
]

def run_tests(log, result_label):
    log("Running test cases...")
    all_pass = True
    for i, (pt, key, exp_ct) in enumerate(test_cases, 1):
        ct = encrypt_verbose(pt, key, log)
        pt2 = decrypt_verbose(ct, key, log)
        ok_enc = (ct == exp_ct)
        ok_dec = (pt2 == pt)
        status = "PASS" if (ok_enc and ok_dec) else "FAIL"
        log(f"Test {i}: PT={format_hex(pt)} Key={format_hex(key)} -> CT={format_hex(ct)} " +
            f"(expected {format_hex(exp_ct)}) Decrypted={format_hex(pt2)} [{status}]\n")
        if not (ok_enc and ok_dec):
            all_pass = False
    result_label.config(text=f"Tests {'PASSED' if all_pass else 'SOME FAILED'}")

# ==================== ADDITIONAL SPECIFICATIONS ====================

# Utility function to calculate hamming distance between two integers' binary representations
def hamming_distance(n1, n2):
    xor_result = n1 ^ n2
    binary = bin(xor_result)[2:]
    return sum(bit == '1' for bit in binary)

# Analyze avalanche effect for single bit change
def analyze_avalanche(pt, key, change_pt=True, log=None):
    """
    Analyze avalanche effect by changing one bit of plaintext or key
    and measuring how many bits change in the ciphertext
    """
    # Original encryption
    original_ct = encrypt_verbose(pt, key, lambda x: None)
    
    results = []
    total_bits = 16  # Total bits in our 16-bit block
    
    # Test each bit position
    for bit_pos in range(total_bits):
        # Create a bitmask with only the bit at 'bit_pos' set to 1
        bit_mask = 1 << bit_pos
        
        # Flip that bit in either plaintext or key
        if change_pt:
            modified_pt = pt ^ bit_mask
            modified_key = key
            log(f"Testing bit {bit_pos}: PT {format_hex(pt)} -> {format_hex(modified_pt)}, Key unchanged")
        else:
            modified_pt = pt
            modified_key = key ^ bit_mask
            log(f"Testing bit {bit_pos}: Key {format_hex(key)} -> {format_hex(modified_key)}, PT unchanged")
        
        # Encrypt with the modified value
        modified_ct = encrypt_verbose(modified_pt, modified_key, lambda x: None)
        
        # Calculate Hamming distance (number of bit differences)
        distance = hamming_distance(original_ct, modified_ct)
        percentage = (distance / total_bits) * 100
        
        result = {
            'bit_position': bit_pos,
            'original_ct': original_ct,
            'modified_ct': modified_ct,
            'bit_diff': distance,
            'percentage': percentage
        }
        results.append(result)
        
        log(f"  Changed bit {bit_pos}: CT {format_hex(original_ct)} -> {format_hex(modified_ct)}, "
            f"Bits changed: {distance}/{total_bits} ({percentage:.1f}%)")
    
    # Calculate average percentage
    avg_percentage = sum(r['percentage'] for r in results) / len(results)
    log(f"\nAvalanche Effect Summary:")
    log(f"Average bits changed: {avg_percentage:.2f}%")
    if avg_percentage > 45:
        log("Good avalanche effect (close to 50% bit changes)")
    else:
        log("Poor avalanche effect (significantly less than 50% bit changes)")
        
    return results

# Block Cipher Modes of Operation

# ECB (Electronic Codebook) Mode
def ecb_encrypt(plaintext, key, log):
    """
    Encrypt using ECB mode (each block independently)
    - plaintext: list of 16-bit blocks
    - key: 16-bit key
    """
    log(f"ECB Encryption with Key: {format_hex(key)}")
    log(f"Input blocks: {[format_hex(block) for block in plaintext]}")
    
    ciphertext = []
    for i, block in enumerate(plaintext):
        log(f"\nProcessing block {i+1}/{len(plaintext)}: {format_hex(block)}")
        ct_block = encrypt_verbose(block, key, log)
        ciphertext.append(ct_block)
        
    log(f"\nECB Encryption complete, output: {[format_hex(block) for block in ciphertext]}")
    return ciphertext

def ecb_decrypt(ciphertext, key, log):
    """
    Decrypt using ECB mode (each block independently)
    - ciphertext: list of 16-bit blocks
    - key: 16-bit key
    """
    log(f"ECB Decryption with Key: {format_hex(key)}")
    log(f"Input blocks: {[format_hex(block) for block in ciphertext]}")
    
    plaintext = []
    for i, block in enumerate(ciphertext):
        log(f"\nProcessing block {i+1}/{len(ciphertext)}: {format_hex(block)}")
        pt_block = decrypt_verbose(block, key, log)
        plaintext.append(pt_block)
        
    log(f"\nECB Decryption complete, output: {[format_hex(block) for block in plaintext]}")
    return plaintext

# CBC (Cipher Block Chaining) Mode
def cbc_encrypt(plaintext, key, iv, log):
    """
    Encrypt using CBC mode (each block XORed with previous ciphertext)
    - plaintext: list of 16-bit blocks
    - key: 16-bit key
    - iv: 16-bit initialization vector
    """
    log(f"CBC Encryption with Key: {format_hex(key)}, IV: {format_hex(iv)}")
    log(f"Input blocks: {[format_hex(block) for block in plaintext]}")
    
    ciphertext = []
    prev_block = iv
    
    for i, block in enumerate(plaintext):
        log(f"\nProcessing block {i+1}/{len(plaintext)}: {format_hex(block)}")
        # XOR plaintext block with previous ciphertext block (or IV for first block)
        xored = block ^ prev_block
        log(f"After XOR with previous: {format_hex(xored)}")
        
        # Encrypt the XORed block
        ct_block = encrypt_verbose(xored, key, log)
        ciphertext.append(ct_block)
        
        # Current ciphertext becomes "previous" for next iteration
        prev_block = ct_block
        
    log(f"\nCBC Encryption complete, output: {[format_hex(block) for block in ciphertext]}")
    return ciphertext

def cbc_decrypt(ciphertext, key, iv, log):
    """
    Decrypt using CBC mode
    - ciphertext: list of 16-bit blocks
    - key: 16-bit key
    - iv: 16-bit initialization vector
    """
    log(f"CBC Decryption with Key: {format_hex(key)}, IV: {format_hex(iv)}")
    log(f"Input blocks: {[format_hex(block) for block in ciphertext]}")
    
    plaintext = []
    prev_block = iv
    
    for i, block in enumerate(ciphertext):
        log(f"\nProcessing block {i+1}/{len(ciphertext)}: {format_hex(block)}")
        
        # Decrypt the current ciphertext block
        decrypted = decrypt_verbose(block, key, log)
        
        # XOR with previous ciphertext block (or IV for first block)
        pt_block = decrypted ^ prev_block
        log(f"After XOR with previous: {format_hex(pt_block)}")
        
        plaintext.append(pt_block)
        
        # Current ciphertext becomes "previous" for next iteration
        prev_block = block
        
    log(f"\nCBC Decryption complete, output: {[format_hex(block) for block in plaintext]}")
    return plaintext

# Convert between string and block list
def text_to_blocks(text, block_size=16):
    """Convert a string to a list of 16-bit blocks"""
    # Convert string to bytes, then to a hex string
    hex_str = binascii.hexlify(text.encode()).decode()
    
    # Ensure the hex string length is even
    if len(hex_str) % 4 != 0:
        hex_str = hex_str + '0' * (4 - len(hex_str) % 4)
    
    # Split into 16-bit blocks (4 hex characters per block)
    blocks = []
    for i in range(0, len(hex_str), 4):
        block = int(hex_str[i:i+4], 16)
        blocks.append(block)
    
    return blocks

def blocks_to_text(blocks):
    """Convert a list of 16-bit blocks back to a string"""
    hex_str = ""
    for block in blocks:
        hex_str += format_hex(block)
    
    # Convert hex string to bytes, then to string (stopping at null bytes)
    try:
        result = binascii.unhexlify(hex_str).decode(errors='ignore').split('\x00')[0]
        return result
    except:
        return "(binary data)"

# File handling functions
def save_to_file(filename, data, mode="text"):
    """Save data to a file (text or CSV format)"""
    if mode == "text":
        with open(filename, 'w') as file:
            file.write(data)
    elif mode == "csv":
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)

def load_from_file(filename, mode="text"):
    """Load data from a file (text or CSV)"""
    if mode == "text":
        with open(filename, 'r') as file:
            return file.read()
    elif mode == "csv":
        with open(filename, 'r', newline='') as file:
            reader = csv.reader(file)
            return list(reader)

# GUI Implementation
class MiniAESApp:
    def __init__(self, root):
        self.root = root
        root.title("Mini-AES Implementation")
        root.geometry("820x680")
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Setup basic encryption/decryption tab
        self.basic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.basic_frame, text="Basic Mode")
        self._setup_basic_tab(self.basic_frame)
        
        # Setup block mode tab
        self.block_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.block_frame, text="Block Mode")
        self._setup_block_tab(self.block_frame)
        
        # Setup avalanche effect analysis tab
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text="Avalanche Analysis")
        self._setup_analysis_tab(self.analysis_frame)
        
        # Initialize log capture
        self.log_entries = []
        
    def _setup_basic_tab(self, parent_frame):
        # Input fields for plaintext & key
        input_frame = ttk.LabelFrame(parent_frame, text="Input")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Plaintext (hex 4-digit):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.plain_entry = ttk.Entry(input_frame, width=6)
        self.plain_entry.grid(row=0, column=1, padx=5, pady=5)
        self.plain_entry.insert(0, "1234")
        
        ttk.Label(input_frame, text="Key (hex 4-digit):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=6)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.key_entry.insert(0, "ABCD")
        
        # Buttons for encryption, decryption, and running tests
        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Encrypt", command=self.do_encrypt).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Decrypt", command=self.do_decrypt).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="Run Tests", command=self.do_tests).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(button_frame, text="Save Log", command=self.save_log).grid(row=0, column=3, padx=5, pady=5)
        
        # Result label to show final output
        self.result_label = ttk.Label(parent_frame, text="Ready")
        self.result_label.pack(padx=10, pady=5)
        
        # Scrolled text area for detailed logs
        log_frame = ttk.LabelFrame(parent_frame, text="Operation Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log = ScrolledText(log_frame, width=60, height=20, state="disabled")
        self.log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _setup_block_tab(self, parent_frame):
        # Block mode input frame
        input_frame = ttk.LabelFrame(parent_frame, text="Block Mode Input")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Mode selection
        ttk.Label(input_frame, text="Mode:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.mode_var = tk.StringVar(value="ECB")
        mode_combobox = ttk.Combobox(input_frame, textvariable=self.mode_var, state="readonly")
        mode_combobox['values'] = ["ECB", "CBC"]
        mode_combobox.grid(row=0, column=1, padx=5, pady=5)
        
        # Input text
        ttk.Label(input_frame, text="Input Text:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.block_input_entry = ttk.Entry(input_frame, width=40)
        self.block_input_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky="we")
        self.block_input_entry.insert(0, "Hello Mini-AES")
        
        # Key
        ttk.Label(input_frame, text="Key (hex 4-digit):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.block_key_entry = ttk.Entry(input_frame, width=6)
        self.block_key_entry.grid(row=2, column=1, padx=5, pady=5)
        self.block_key_entry.insert(0, "ABCD")
        
        # IV for CBC mode
        ttk.Label(input_frame, text="IV (hex 4-digit, CBC only):").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        self.iv_entry = ttk.Entry(input_frame, width=6)
        self.iv_entry.grid(row=2, column=3, padx=5, pady=5)
        self.iv_entry.insert(0, "1234")
        
        # File handling
        file_frame = ttk.Frame(parent_frame)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(file_frame, text="Load Input", command=self.load_input_file).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(file_frame, text="Export Result", command=self.save_block_result).grid(row=0, column=1, padx=5, pady=5)
        
        # Buttons for encryption and decryption
        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Encrypt Blocks", command=self.do_block_encrypt).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Decrypt Blocks", command=self.do_block_decrypt).grid(row=0, column=1, padx=5, pady=5)
        
        # Result display
        result_frame = ttk.LabelFrame(parent_frame, text="Result")
        result_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.block_result_var = tk.StringVar()
        ttk.Entry(result_frame, textvariable=self.block_result_var, state="readonly", width=60).pack(
            fill=tk.X, padx=5, pady=5)
        
        # Log display
        log_frame = ttk.LabelFrame(parent_frame, text="Block Operation Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.block_log = ScrolledText(log_frame, width=60, height=15, state="disabled")
        self.block_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _setup_analysis_tab(self, parent_frame):
        # Analysis input frame
        input_frame = ttk.LabelFrame(parent_frame, text="Avalanche Effect Analysis")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Plaintext
        ttk.Label(input_frame, text="Plaintext (hex 4-digit):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.analysis_pt_entry = ttk.Entry(input_frame, width=6)
        self.analysis_pt_entry.grid(row=0, column=1, padx=5, pady=5)
        self.analysis_pt_entry.insert(0, "1234")
        
        # Key
        ttk.Label(input_frame, text="Key (hex 4-digit):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.analysis_key_entry = ttk.Entry(input_frame, width=6)
        self.analysis_key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.analysis_key_entry.insert(0, "ABCD")
        
        # Analysis type
        ttk.Label(input_frame, text="Change:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.analysis_type_var = tk.StringVar(value="Plaintext")
        type_combobox = ttk.Combobox(input_frame, textvariable=self.analysis_type_var, state="readonly")
        type_combobox['values'] = ["Plaintext", "Key"]
        type_combobox.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Run Avalanche Analysis", command=self.do_avalanche_analysis).grid(
            row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Save Analysis", command=self.save_analysis).grid(
            row=0, column=1, padx=5, pady=5)
        
        # Analysis log
        log_frame = ttk.LabelFrame(parent_frame, text="Analysis Results")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.analysis_log = ScrolledText(log_frame, width=60, height=20, state="disabled")
        self.analysis_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def append_log(self, msg, log_widget=None):
        if log_widget is None:
            log_widget = self.log
            
        log_widget.config(state="normal")
        log_widget.insert("end", msg + "\n")
        log_widget.see("end")
        log_widget.config(state="disabled")
        
        # Save to log entries for potential file export
        self.log_entries.append(msg)

    def clear_log(self, log_widget=None):
        if log_widget is None:
            log_widget = self.log
            
        log_widget.config(state="normal")
        log_widget.delete("1.0", "end")
        log_widget.config(state="disabled")
        
        # Clear log entries
        self.log_entries = []

    def do_encrypt(self):
        self.clear_log()
        try:
            pt = int(self.plain_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            if pt > 0xFFFF or key > 0xFFFF:
                raise ValueError("Input values must be 16-bit (0-FFFF)")
            ct = encrypt_verbose(pt, key, self.append_log)
            self.result_label.config(text=f"Ciphertext: {format_hex(ct)}")
        except ValueError as e:
            self.append_log(f"Error: {str(e)}")
            self.result_label.config(text="Invalid input!")

    def do_decrypt(self):
        self.clear_log()
        try:
            ct = int(self.plain_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            if ct > 0xFFFF or key > 0xFFFF:
                raise ValueError("Input values must be 16-bit (0-FFFF)")
            pt = decrypt_verbose(ct, key, self.append_log)
            self.result_label.config(text=f"Plaintext: {format_hex(pt)}")
        except ValueError as e:
            self.append_log(f"Error: {str(e)}")
            self.result_label.config(text="Invalid input!")

    def do_tests(self):
        self.clear_log()
        run_tests(self.append_log, self.result_label)
        
    def save_log(self):
        if not self.log_entries:
            tk.messagebox.showinfo("Save Log", "No log entries to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            
        if filename:
            save_to_file(filename, "\n".join(self.log_entries))
            tk.messagebox.showinfo("Save Log", f"Log saved to {filename}")
            
    def do_block_encrypt(self):
        self.clear_log(self.block_log)
        
        try:
            # Get the key and optional IV
            key = int(self.block_key_entry.get(), 16)
            mode = self.mode_var.get()
            
            # Convert input text to blocks
            input_text = self.block_input_entry.get()
            blocks = text_to_blocks(input_text)
            
            # Encrypt based on selected mode
            if mode == "ECB":
                encrypted_blocks = ecb_encrypt(blocks, key, 
                                               lambda msg: self.append_log(msg, self.block_log))
            else:  # CBC
                iv = int(self.iv_entry.get(), 16)
                encrypted_blocks = cbc_encrypt(blocks, key, iv, 
                                                lambda msg: self.append_log(msg, self.block_log))
                
            # Store the blocks for potential decryption (as hex strings for display)
            self.last_encrypted_blocks = encrypted_blocks
            self.last_encryption_mode = mode
            self.last_iv = int(self.iv_entry.get(), 16) if mode == "CBC" else None
            
            # Display result as hex strings
            hex_blocks = [format_hex(block) for block in encrypted_blocks]
            result_text = " ".join(hex_blocks)
            self.block_result_var.set(result_text)
            
        except ValueError as e:
            self.append_log(f"Error: {str(e)}", self.block_log)
            self.block_result_var.set("Error in encryption")
            
    def do_block_decrypt(self):
        self.clear_log(self.block_log)
        
        try:
            # Get the key and optional IV
            key = int(self.block_key_entry.get(), 16)
            mode = self.mode_var.get()
            
            # Check if we have blocks to decrypt or parse from input
            input_text = self.block_result_var.get()
            if input_text and input_text != "Error in encryption":
                # Parse hex blocks from the result field
                try:
                    blocks = [int(block, 16) for block in input_text.split()]
                except ValueError:
                    # If parsing fails, try treating as text input
                    blocks = text_to_blocks(self.block_input_entry.get())
            else:
                # No result, use input text
                blocks = text_to_blocks(self.block_input_entry.get())
            
            # Decrypt based on selected mode
            if mode == "ECB":
                decrypted_blocks = ecb_decrypt(blocks, key, 
                                               lambda msg: self.append_log(msg, self.block_log))
            else:  # CBC
                iv = int(self.iv_entry.get(), 16)
                decrypted_blocks = cbc_decrypt(blocks, key, iv, 
                                                lambda msg: self.append_log(msg, self.block_log))
                
            # Convert blocks back to text
            result_text = blocks_to_text(decrypted_blocks)
            self.block_result_var.set(result_text)
            
        except ValueError as e:
            self.append_log(f"Error: {str(e)}", self.block_log)
            self.block_result_var.set("Error in decryption")
    
    def load_input_file(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            
        if filename:
            try:
                content = load_from_file(filename)
                self.block_input_entry.delete(0, tk.END)
                self.block_input_entry.insert(0, content)
                self.append_log(f"Loaded content from {filename}", self.block_log)
            except Exception as e:
                self.append_log(f"Error loading file: {str(e)}", self.block_log)
    
    def save_block_result(self):
        result = self.block_result_var.get()
        if not result:
            tk.messagebox.showinfo("Save Result", "No result to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            
        if filename:
            save_to_file(filename, result)
            tk.messagebox.showinfo("Save Result", f"Result saved to {filename}")
    
    def do_avalanche_analysis(self):
        self.clear_log(self.analysis_log)
        
        try:
            pt = int(self.analysis_pt_entry.get(), 16)
            key = int(self.analysis_key_entry.get(), 16)
            
            if pt > 0xFFFF or key > 0xFFFF:
                raise ValueError("Input values must be 16-bit (0-FFFF)")
                
            change_pt = self.analysis_type_var.get() == "Plaintext"
            
            # Run the avalanche analysis
            self.append_log(f"Avalanche Effect Analysis", self.analysis_log)
            self.append_log(f"Plaintext: {format_hex(pt)}", self.analysis_log)
            self.append_log(f"Key: {format_hex(key)}", self.analysis_log)
            self.append_log(f"Changing {'plaintext' if change_pt else 'key'} bits one by one", self.analysis_log)
            self.append_log(f"--------------------------------------------------", self.analysis_log)
            
            results = analyze_avalanche(pt, key, change_pt, lambda msg: self.append_log(msg, self.analysis_log))
            
            # Store the results for potential export
            self.last_avalanche_results = results
            self.last_avalanche_type = "plaintext" if change_pt else "key"
            
        except ValueError as e:
            self.append_log(f"Error: {str(e)}", self.analysis_log)
    
    def save_analysis(self):
        if not hasattr(self, 'last_avalanche_results'):
            tk.messagebox.showinfo("Save Analysis", "No analysis results to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")])
            
        if filename:
            # Prepare the data for CSV format
            header = ["Bit Position", "Original CT", "Modified CT", "Bits Changed", "Percentage"]
            rows = [header]
            
            for result in self.last_avalanche_results:
                row = [
                    result['bit_position'],
                    format_hex(result['original_ct']),
                    format_hex(result['modified_ct']),
                    result['bit_diff'],
                    f"{result['percentage']:.2f}%"
                ]
                rows.append(row)
                
            save_to_file(filename, rows, mode="csv")
            tk.messagebox.showinfo("Save Analysis", f"Analysis saved to {filename}")

# Main program
if __name__ == '__main__':
    root = tk.Tk()
    app = MiniAESApp(root)
    root.mainloop()
