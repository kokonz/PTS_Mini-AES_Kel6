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
