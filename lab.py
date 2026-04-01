import time
import base64


# AES constants
S_BOX = [
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

RCON = [
	0x01, 0x02, 0x04, 0x08, 0x10,
	0x20, 0x40, 0x80, 0x1B, 0x36,
	0x6C, 0xD8, 0xAB, 0x4D,
]


def gf_mul(a, b):
	# Nhan hai phan tu trong truong huu han GF(2^8) dung cho MixColumns.
	result = 0
	value = a
	count = b
	while count:
		if count & 1:
			result ^= value
		high_bit = value & 0x80
		value = (value << 1) & 0xFF
		if high_bit:
			value ^= 0x1B
		count >>= 1
	return result

# Chuyen doi chuoi <-> byte theo encoding ro rang (mac dinh UTF-8).
def text_to_bytes(text, encoding="utf-8"):
    return list(text.encode(encoding))

def bytes_to_text(data, encoding="utf-8"):
    return bytes(data).decode(encoding)

def bytes_to_hex(data):
    return "".join(format(b, "02x") for b in data)

def bytes_to_base64(data):
    return base64.b64encode(bytes(data)).decode("ascii")

# PKCS#7 padding: bo sung byte de du lieu co do dai chia het cho block size (16 byte).
def pad_pkcs7(data, block_size=16):
	# PKCS#7: bo sung N byte, moi byte deu co gia tri N.
	pad_len = block_size - (len(data) % block_size)
	if pad_len == 0:
		pad_len = block_size
	return data + [pad_len] * pad_len

# PKCS#7 unpadding: kiem tra va bo phan dem sau khi giai ma.
def unpad_pkcs7(data):
	# Kiem tra va bo phan dem PKCS#7 sau khi giai ma.
	if not data:
		raise ValueError("Du lieu rong, khong the bo dem")
	pad_len = data[-1]
	if pad_len < 1 or pad_len > 16:
		raise ValueError("Dem PKCS7 khong hop le")
	for i in range(1, pad_len + 1):
		if data[-i] != pad_len:
			raise ValueError("Dem PKCS7 khong hop le")
	return data[:-pad_len]

# Chuyen doi du lieu giua dang byte array va state 4x4 (theo cot) su dung trong AES. State la cau truc du lieu chinh duoc thao tac trong cac buoc ma hoa/giai ma.
def to_state(block):
	# Chuyen 16 byte thanh ma tran state 4x4 (theo cot) cua AES.
	state = [[0] * 4 for _ in range(4)]
	for i in range(16):
		row = i % 4
		col = i // 4
		state[row][col] = block[i]
	return state

# Chuyen doi du lieu tu state 4x4 ve lai dang byte array 16 byte (theo cot) sau khi thuc hien cac buoc ma hoa/giai ma. State la cau truc du lieu chinh duoc thao tac trong cac buoc ma hoa/giai ma.
def from_state(state):
	# Chuyen state 4x4 ve lai mang 16 byte (theo cot).
	block = [0] * 16
	for i in range(16):
		row = i % 4
		col = i // 4
		block[i] = state[row][col]
	return block


def add_round_key(state, round_key):
	# XOR state voi round key hien tai.
	for c in range(4):
		for r in range(4):
			state[r][c] ^= round_key[c * 4 + r]


def sub_bytes(state):
	# Thay the tung byte theo S-Box.
	for r in range(4):
		for c in range(4):
			state[r][c] = S_BOX[state[r][c]]


def inv_sub_bytes(state):
	# Phep nguoc cua SubBytes khi giai ma.
	for r in range(4):
		for c in range(4):
			state[r][c] = INV_S_BOX[state[r][c]]


def shift_rows(state):
	# Dich trai hang r di r buoc (r = 1..3).
	for r in range(1, 4):
		state[r] = state[r][r:] + state[r][:r]


def inv_shift_rows(state):
	# Phep nguoc cua ShiftRows.
	for r in range(1, 4):
		state[r] = state[r][-r:] + state[r][:-r]


def mix_columns(state):
	# Tron tung cot state bang phep nhan trong GF(2^8).
	for c in range(4):
		s0 = state[0][c]
		s1 = state[1][c]
		s2 = state[2][c]
		s3 = state[3][c]
		state[0][c] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3
		state[1][c] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3
		state[2][c] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3)
		state[3][c] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2)


def inv_mix_columns(state):
	# Phep nguoc cua MixColumns khi giai ma.
	for c in range(4):
		s0 = state[0][c]
		s1 = state[1][c]
		s2 = state[2][c]
		s3 = state[3][c]
		state[0][c] = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3, 9)
		state[1][c] = gf_mul(s0, 9) ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13)
		state[2][c] = gf_mul(s0, 13) ^ gf_mul(s1, 9) ^ gf_mul(s2, 14) ^ gf_mul(s3, 11)
		state[3][c] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2, 9) ^ gf_mul(s3, 14)


def rot_word(word):
	return word[1:] + word[:1]


def sub_word(word):
	return [S_BOX[b] for b in word]


def expand_key(key_bytes):
	# Ho tro AES-128/192/256 voi khoa 16/24/32 byte.
	if len(key_bytes) not in (16, 24, 32):
		raise ValueError("Khoa AES phai co do dai 16, 24 hoac 32 byte")

	nk = len(key_bytes) // 4
	nb = 4
	nr_map = {4: 10, 6: 12, 8: 14}
	nr = nr_map[nk]
	total_words = nb * (nr + 1)

	words = []
	for i in range(nk):
		words.append(key_bytes[4 * i:4 * i + 4])

	for i in range(nk, total_words):
		temp = words[i - 1][:]
		if i % nk == 0:
			# Moi 4 tu: xoay, qua S-Box, roi XOR voi RCON.
			temp = sub_word(rot_word(temp))
			temp[0] ^= RCON[(i // nk) - 1]
		elif nk > 6 and i % nk == 4:
			# Rieng AES-256 co them buoc SubWord tai vi tri i % nk == 4.
			temp = sub_word(temp)
		new_word = [words[i - nk][j] ^ temp[j] for j in range(4)]
		words.append(new_word)

	round_keys = []
	for r in range(nr + 1):
		round_key = []
		for i in range(4):
			round_key.extend(words[r * 4 + i])
		round_keys.append(round_key)
	return round_keys


def aes_encrypt_block(block, round_keys):
	# Ma hoa 1 block 16 byte theo so round phu hop voi do dai khoa.
	state = to_state(block)
	nr = len(round_keys) - 1
	# Round 0: chi AddRoundKey.
	add_round_key(state, round_keys[0])

	# Round 1..(nr-1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
	for r in range(1, nr):
		sub_bytes(state)
		shift_rows(state)
		mix_columns(state)
		add_round_key(state, round_keys[r])

	# Round cuoi: bo qua MixColumns.
	sub_bytes(state)
	shift_rows(state)
	add_round_key(state, round_keys[nr])

	return from_state(state)


def aes_decrypt_block(block, round_keys):
	# Giai ma 1 block 16 byte theo thu tu nguoc cua ma hoa.
	state = to_state(block)
	nr = len(round_keys) - 1
	# Bat dau tu round key cuoi.
	add_round_key(state, round_keys[nr])

	# Round (nr-1)..1: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns.
	for r in range(nr - 1, 0, -1):
		inv_shift_rows(state)
		inv_sub_bytes(state)
		add_round_key(state, round_keys[r])
		inv_mix_columns(state)

	# Round cuoi khi giai ma: khong InvMixColumns.
	inv_shift_rows(state)
	inv_sub_bytes(state)
	add_round_key(state, round_keys[0])

	return from_state(state)


def aes_encrypt_ecb(plain_bytes, key_bytes):
	round_keys = expand_key(key_bytes)
	padded = pad_pkcs7(plain_bytes, 16)

	cipher = []
	for i in range(0, len(padded), 16):
		block = padded[i:i + 16]
		cipher.extend(aes_encrypt_block(block, round_keys))
	return cipher


def aes_decrypt_ecb(cipher_bytes, key_bytes):
	if len(cipher_bytes) % 16 != 0:
		raise ValueError("Do dai ban ma phai chia het cho 16")

	round_keys = expand_key(key_bytes)
	plain = []
	for i in range(0, len(cipher_bytes), 16):
		block = cipher_bytes[i:i + 16]
		plain.extend(aes_decrypt_block(block, round_keys))

	return unpad_pkcs7(plain)


def main():
	print("=== CHUONG TRINH MA HOA/GIAI MA AES (128/192/256) ===")
	print("Nhap chuoi toi thieu 16 ky tu (UTF-8):")
	user_input = input("> ").strip()
	user_bytes_len = len(user_input.encode("utf-8"))

	if user_bytes_len < 16:
		print("Loi: Du lieu phai co do dai >= 16 ky tu (UTF-8).")
		return

	print("Nhap khoa AES (16/24/32 byte - UTF-8):")
	key_text = input(">")
	key_bytes_len = len(key_text.encode("utf-8"))
	if key_bytes_len not in (16, 24, 32):
		print("Loi: Khoa phai co do dai 16, 24 hoac 32 byte (UTF-8).")
		return

	plain_bytes = text_to_bytes(user_input, "utf-8")
	key_bytes = text_to_bytes(key_text, "utf-8")

	t1 = time.perf_counter()
	cipher_bytes = aes_encrypt_ecb(plain_bytes, key_bytes)
	t2 = time.perf_counter()

	t3 = time.perf_counter()
	recovered_bytes = aes_decrypt_ecb(cipher_bytes, key_bytes)
	t4 = time.perf_counter()

	recovered_text = bytes_to_text(recovered_bytes, "utf-8")

	print("\n--- KET QUA ---")
	print("Ban ro:", user_input)
	print(f"Do dai ban ro: {user_bytes_len} byte (UTF-8)")
	print(f"Khoa ({key_bytes_len} byte):", key_text)
	print("Ban ma (hex):   ", bytes_to_hex(cipher_bytes))
	print("Ban ma (base64):", bytes_to_base64(cipher_bytes))
	print("Giai ma:", recovered_text)
	print(f"Thoi gian ma hoa : {(t2 - t1) * 1000:.6f} ms")
	print(f"Thoi gian giai ma: {(t4 - t3) * 1000:.6f} ms")

if __name__ == "__main__":
    main()
