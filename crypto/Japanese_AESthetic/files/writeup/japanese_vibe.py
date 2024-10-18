from Cryptodome.Cipher import AES

def str_to_hex_num(str):
    return hex(int(str.encode().hex(), 16))


def fight(str1, str2):
    hex_res = 0x00
    if int(str1, 16) >= int(str2, 16):
        hex_res = hex(int(str1, 16) % int(str2, 16))
    else:
        hex_res = hex(int(str2, 16) % int(str1, 16))
    return hex_res


def crypt_mes(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext = cipher.encrypt(data)
    return ciphertext, cipher.nonce

def decrypt_mes(key, ciphertext, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt(ciphertext)
    return data


if __name__ == '__main__':
    flag = "SSLCTF{I_H4te_F0re1gn_DicTi0nar1es}"
    alive_jp = "kumokitsunenekofukuronezumiarai"
    alive_ch = "xionghumaodaishuhuanxiong"
    dead_jp = "ashikikurumakangenshi"
    dead_ch = "zumucheganyuanzi"
    alive_res = fight(str_to_hex_num(alive_ch), str_to_hex_num(alive_jp))
    dead_res = fight(str_to_hex_num(dead_ch), str_to_hex_num(dead_jp))
    final_res = fight(dead_res, alive_res)[2:]
    if len(final_res) % 2 !=  0:
        final_res = "0" + final_res
    crypted_text, nonce = crypt_mes(bytes.fromhex(final_res), bytearray(flag, "UTF-8"))
    print(final_res)
    print(str(nonce))
    print(str(crypted_text))
    decrypted_text = decrypt_mes(bytes.fromhex(final_res), crypted_text, nonce)
    print(decrypted_text)
    nonce = b"\xad\x06\n\x94\xe7\x9e\x15\x0ed \x9at\x0b\x89\x01\x8d"
    crypted_text = b"\xbd+\x1d\x7f\xaf7\\\x1e\x14\xfd\x10\xdb\xeaL\x81\x88P\xb8F\xb1\xedRF\xea\xa4\xe3\xa7\xa0\x0f\xe7\xd0+\xa5\xa4v"
    decrypted_text = decrypt_mes(bytes.fromhex(final_res), crypted_text, nonce)
    print(decrypted_text)