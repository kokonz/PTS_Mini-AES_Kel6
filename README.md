# Project Tengah Semester - Kriptografi B

Dosen Pengampu : Ibu Hafara Firdausi, S.Kom., M.Kom.

_Kelompok 6_

| No  | Nama                     | NRP        |
| --- | ------------------------ | ---------- |
| 1   | Hazwan Adhikara Nasution | 5027231017 |
| 2   | Rafael Gunawan           | 5027231019 |
| 3   | Tio Axellino Irin        | 5027231065 |
| 4   | Azza Farichi Tjahjono    | 5027231071 |
| 5   | Nabiel Nizar Anwari      | 5027231087 |

# Mini-AES

Mini-AES adalah versi sederhana dari AES yang biasanya dan disini juga untuk keperluan edukasi. Proyek ini mengimplementasikan enkripsi dan dekripsi 16-bit dengan (GUI) untuk memahami konsep dasar cipher modern.

## Spesifikasi Algoritma

### Representasi Data

**Plaintext dan Kunci:** 16 bit, dalam matriks 2x2 nibble (4 bit).
ex: `0x1234` -> `[[0x1, 0x2], [0x3, 0x4]]`.


### Operasi Enkripsi

- **SubNibbles:** Ganti nibble dengan S-Box `[9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7]`.


- **ShiftRows:** Tukar elemen baris kedua.


- **MixColumns:** Campur kolom di GF(2^4) dengan matriks `[1, 4; 4, 1]`.


- **AddRoundKey:** XOR state dengan kunci ronde.


- **Struktur:** AddRoundKey awal -> 2 ronde penuh (SubNibbles, ShiftRows, MixColumns, AddRoundKey) -> Ronde akhir (tanpa MixColumns).


### Ekspansi Kunci

- Kunci 16-bit jadi 4 nibble (`w0-w3`).


- Kunci ronde baru: temp = `S-Box[w3] XOR rcon[i]`, lalu XOR berantai.


- `rcon`: `[0x1, 0x2, 0x4]`.


## Flowchart

![Flowchart Image](https://github.com/kokonz/PTS_Mini-AES_Kel6/blob/main/flowchart/gambar-flowchart.jpg)


## Implementasi Program

- **Bahasa**: Python 3.x
- **Pustaka**: Tkinter (GUI)
- **Fitur**: Enkripsi, dekripsi, ekspansi kunci, GUI, dan test case otomatis.


### Alur Singkat Program

1. **Input**: Masukkan plaintext dan key dalam 4 digit heksadesimal (contoh: `0x1234`, `0xABCD`) melalui GUI.
2. **Proses Enkripsi** (ditampilkan step-by-step di log GUI):
   - **AddRoundKey awal**: XOR plaintext dengan round key 0.
   - **Ronde 1 & 2**:
     - SubNibbles: Ganti setiap nibble dengan S-Box.
     - ShiftRows: Tukar elemen baris kedua.
     - MixColumns: Campur kolom menggunakan tabel `mult4`.
     - AddRoundKey: XOR dengan round key 1 atau 2.
   - **Ronde Akhir**:
     - SubNibbles
     - ShiftRows
     - AddRoundKey (tanpa MixColumns)
3. **Output**: Tampilkan ciphertext hasil akhir (contoh: `0x18C2`) di label GUI.
4. **Test Case**: Tombol "Run Tests" menjalankan 5 test case otomatis dengan hasil PASS/FAIL.


## Test Case

- Plaintext: `0x1234, etc`


- Kunci: `0xABCD, etc`


- Ciphertext: `0x18C2, etc`


(ditulis hardcode)


**Langkah Enkripsi dan Deskripsi:**


Untuk langkahnya sama seperti enkripsi dan deskripsi sebelumny. Namun, pada test case berfokus pada validasi program dengan mencocokan hasil enkripsi dan deskripsi program, dengan variabel yang sudah di set pada Program. Jika cocok maka output akan menghasilkan `PASS` yang berarti Test Case sempurna di selesaikan.


## Analisis Mini-AES

**Kelebihan:**


- Mudah dipahami dan mirip AES asli.
- Cocok untuk belajar substitusi dan difusi.


**Keterbatasan:**


- Kunci 16-bit lemah (brute-force mudah).
- Blok kecil, tidak praktis untuk data besar.


## Avalanche Effect Analysis

Ini adalah hasil jika kita menjalankan `avalanche test` dengan menggunakan plaintext "1234" dan key "ABCD":
```
Avalanche Effect Analysis
Plaintext: 1234
Key: ABCD
Changing plaintext bits one by one
--------------------------------------------------
Testing bit 0: PT 1234 -> 1235, Key unchanged
  Changed bit 0: CT 18C2 -> 3EA8, Bits changed: 7/16 (43.8%)
Testing bit 1: PT 1234 -> 1236, Key unchanged
  Changed bit 1: CT 18C2 -> 578F, Bits changed: 9/16 (56.2%)
Testing bit 2: PT 1234 -> 1230, Key unchanged
  Changed bit 2: CT 18C2 -> B44C, Bits changed: 8/16 (50.0%)
Testing bit 3: PT 1234 -> 123C, Key unchanged
  Changed bit 3: CT 18C2 -> 40FA, Bits changed: 6/16 (37.5%)
Testing bit 4: PT 1234 -> 1224, Key unchanged
  Changed bit 4: CT 18C2 -> 21E5, Bits changed: 8/16 (50.0%)
Testing bit 5: PT 1234 -> 1214, Key unchanged
  Changed bit 5: CT 18C2 -> A61B, Bits changed: 11/16 (68.8%)
Testing bit 6: PT 1234 -> 1274, Key unchanged
  Changed bit 6: CT 18C2 -> 0B38, Bits changed: 9/16 (56.2%)
Testing bit 7: PT 1234 -> 12B4, Key unchanged
  Changed bit 7: CT 18C2 -> B769, Bits changed: 11/16 (68.8%)
Testing bit 8: PT 1234 -> 1334, Key unchanged
  Changed bit 8: CT 18C2 -> EEB1, Bits changed: 11/16 (68.8%)
Testing bit 9: PT 1234 -> 1034, Key unchanged
  Changed bit 9: CT 18C2 -> 0598, Bits changed: 8/16 (50.0%)
Testing bit 10: PT 1234 -> 1634, Key unchanged
  Changed bit 10: CT 18C2 -> CD43, Bits changed: 7/16 (43.8%)
Testing bit 11: PT 1234 -> 1A34, Key unchanged
  Changed bit 11: CT 18C2 -> 41E6, Bits changed: 6/16 (37.5%)
Testing bit 12: PT 1234 -> 0234, Key unchanged
  Changed bit 12: CT 18C2 -> 3448, Bits changed: 6/16 (37.5%)
Testing bit 13: PT 1234 -> 3234, Key unchanged
  Changed bit 13: CT 18C2 -> EEAE, Bits changed: 10/16 (62.5%)
Testing bit 14: PT 1234 -> 5234, Key unchanged
  Changed bit 14: CT 18C2 -> 512F, Bits changed: 9/16 (56.2%)
Testing bit 15: PT 1234 -> 9234, Key unchanged
  Changed bit 15: CT 18C2 -> F0F5, Bits changed: 9/16 (56.2%)

Avalanche Effect Summary:
Average bits changed: 52.73%
Good avalanche effect (close to 50% bit changes)
```

Dari hasil diatas, kami mengubah **bit dari plaintext** nya dan dapat kita tarik informasi:

Hasil pengujian menunjukkan rata-rata 52.73% bit berubah di ciphertext, menunjukkan efek avalanche yang sangat baik (ideal mendekati 50%).
Ini membuktikan bahwa implementasi Mini-AES memiliki difusi yang kuat terhadap perubahan kecil pada input.

## Mode Operasi Block Cipher

Sebagai fitur tambahan, kami mengimplementasikan dua mode operasi block cipher yang umum digunakan dalam kriptografi: ECB (Electronic Codebook) dan CBC (Cipher Block Chaining).

### ECB (Electronic Codebook)

ECB adalah mode operasi paling sederhana di mana setiap blok plaintext dienkripsi secara independen menggunakan kunci yang sama.

**Alur Enkripsi ECB:**
1. Bagi plaintext menjadi blok-blok 16-bit
2. Untuk setiap blok plaintext:
   - Enkripsi blok menggunakan Mini-AES dengan kunci yang sama
   - Tambahkan hasil enkripsi ke ciphertext
3. Gabungkan semua blok ciphertext untuk mendapatkan hasil akhir

**Implementasi Enkripsi ECB:**
```python
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
```

**Alur Dekripsi ECB:**
1. Bagi ciphertext menjadi blok-blok 16-bit
2. Untuk setiap blok ciphertext:
   - Dekripsi blok menggunakan Mini-AES dengan kunci yang sama
   - Tambahkan hasil dekripsi ke plaintext
3. Gabungkan semua blok plaintext untuk mendapatkan hasil akhir

**Implementasi Dekripsi ECB:**
```python
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
```

**Kelebihan ECB:**
- Sederhana dan mudah diimplementasikan
- Memungkinkan akses acak ke blok data

**Kelemahan ECB:**
- Blok plaintext yang identik menghasilkan blok ciphertext yang identik
- Tidak menyembunyikan pola data dengan baik
- Rentan terhadap serangan replay dan substitusi

### CBC (Cipher Block Chaining)

CBC adalah mode operasi di mana setiap blok plaintext di-XOR dengan blok ciphertext sebelumnya sebelum dienkripsi.

**Alur Enkripsi CBC:**
1. Inisialisasi vektor (IV) secara acak
2. Bagi plaintext menjadi blok-blok 16-bit
3. Untuk blok pertama:
   - XOR blok plaintext dengan IV
   - Enkripsi hasil XOR menggunakan Mini-AES
   - Simpan hasil sebagai blok ciphertext pertama
4. Untuk blok selanjutnya:
   - XOR blok plaintext dengan blok ciphertext sebelumnya
   - Enkripsi hasil XOR menggunakan Mini-AES
   - Simpan hasil sebagai blok ciphertext berikutnya
5. Gabungkan IV dan semua blok ciphertext untuk mendapatkan hasil akhir

**Implementasi Enkripsi CBC:**
```python
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
```

**Alur Dekripsi CBC:**
1. Ekstrak IV dari awal ciphertext
2. Bagi ciphertext menjadi blok-blok 16-bit (tidak termasuk IV)
3. Untuk blok pertama:
   - Dekripsi blok ciphertext menggunakan Mini-AES
   - XOR hasil dekripsi dengan IV
   - Simpan hasil sebagai blok plaintext pertama
4. Untuk blok selanjutnya:
   - Simpan blok ciphertext saat ini
   - Dekripsi blok ciphertext menggunakan Mini-AES
   - XOR hasil dekripsi dengan blok ciphertext sebelumnya
   - Simpan hasil sebagai blok plaintext berikutnya
5. Gabungkan semua blok plaintext untuk mendapatkan hasil akhir

**Implementasi Dekripsi CBC:**
```python
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
```

**Kelebihan CBC:**
- Menyembunyikan pola dalam plaintext
- Blok plaintext yang identik menghasilkan ciphertext yang berbeda
- Kesalahan dalam satu blok hanya mempengaruhi dua blok plaintext saat dekripsi

**Kelemahan CBC:**
- Tidak dapat diparalelkan saat enkripsi
- Memerlukan IV yang acak dan unik
- Rentan terhadap bit-flipping attack

### Perbandingan ECB dan CBC

Mode CBC menawarkan keamanan yang lebih baik dibandingkan ECB karena:
1. CBC menyembunyikan pola dalam plaintext dengan lebih baik
2. Blok plaintext yang identik menghasilkan blok ciphertext yang berbeda
3. Perubahan satu bit dalam IV atau blok ciphertext memengaruhi semua blok plaintext berikutnya (efek avalanche pada level blok)

Dalam implementasi kami, mode CBC memastikan hasil enkripsi lebih aman dengan menambahkan IV di awal ciphertext, sehingga pesan yang sama akan menghasilkan ciphertext yang berbeda setiap kali dienkripsi.

### Contoh Konversi Data

Untuk mengonversi antara string teks dan blok 16-bit, kami mengimplementasikan fungsi berikut:

```python
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
```
