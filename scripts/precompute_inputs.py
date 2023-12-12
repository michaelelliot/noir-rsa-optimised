import re
import math
import decimal

def bytes_to_hex_array(bstr):
    return ['0x' + hex(b)[2:].zfill(2) for b in list(bstr)]

def hex_to_noir_array(s):
    if type(s) == str and s[:2] == '0x':
        s = s[2:]
        if len(s) % 2 != 0: s = s.zfill(len(s) + 1)
        s = bytes.fromhex(s)
    dg1_hex_repr = ','.join(bytes_to_hex_array(s))
    dg1_hex_repr = '\t' + re.sub(r'(([^,]+,){15}[^,]+),', r'\1,\n\t', dg1_hex_repr)
    return dg1_hex_repr

def print_hex_as_noir_array(name, s):
    if type(s) == str and s[:2] == '0x':
        s = s[2:]
        if len(s) % 2 != 0: s = s.zfill(len(s) + 1)
        s = bytes.fromhex(s)
    dg1_hex_repr = hex_to_noir_array(s)
    print(f"let {name}: [u8; {len(s)}] = [\n{dg1_hex_repr}];")
    print()

def obj_to_toml(obj):
    toml = ""
    for k, v in obj.items():
        if type(v) == int:
            toml += f'{k} = "{v}"\n'
            # print(k, v)
        elif type(v) == bytes:
            b_array = [str(b_code) for b_code in list(v)]
            toml += f'{k} = ["' + '","'.join(b_array) + '"]\n'
            # print(k, v, f"len={len(list(v))}")
        else:
            raise Exception(f"Unknown value type: {type(v)}")
    return toml

def get_final_e(sig, pubkey):
    final_e = sig
    for _ in range(0, 16): final_e = final_e * final_e % pubkey
    return final_e

def get_sig_quotient(sig, pubkey, final_e):
    decimal.getcontext().prec = 10000
    dividend = decimal.Decimal(sig * final_e)
    sig_quotient = math.floor(dividend / decimal.Decimal(pubkey))
    return sig_quotient

def int_to_bytes(num, byteorder='big'):
    bytes_length = (num.bit_length() + 7) // 8
    return num.to_bytes(bytes_length, byteorder=byteorder)

# Returns base ^ e % modulus
def rsa_mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2: result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def encrypt_and_decrypt(data_to_encrypt, pub_keypair, priv_keypair):
    encrypted = rsa_mod_exp(int.from_bytes(data_to_encrypt, byteorder='big'), priv_keypair[0], priv_keypair[1])
    print("encrypted:", hex(encrypted))

    decrypted = rsa_mod_exp(encrypted, pub_keypair[0], pub_keypair[1])
    print("decrypted:", int_to_bytes(decrypted))
    print()

def main():
    # The data to encrypt
    data_to_encrypt = b"https://www.youtube.com/watch?v=cbyTXVm9NPI"

    # 2048 bit keys
    pub_keypair = (65537, 16999730304730078253817608057972467347309223968496624296294968781316605440148409563011329841844262314146357841699028072349108904308417977727158661795088751574569482232520257575237485690201475478505913333557784829158773508924589344834125875828400628083793356503799521926680717206324504037691491546965239700027470441504714957539653468685572969246181396487877216267521187549795121184083468359258757946140192861965869509330741710040992538932823214070774019031529198127002431470028260248221159298260478349552980547430585921925972953125574098935759013232909510947861450758290172657746314751509889908440852993088278450756451)
    priv_keypair = (14831996869317574416791901197107979964281877817395318328000157390721020172844134745456579342305185149196465224046728186778797429671107007742785484252302894777513206189717386028534712174278962538123016378730093482022348737969513690550609847565008284081225935347776930035973624210104752138108236365037649053932211172578265774545544224924950285135230062482780552739848416248165308930342754999576723548185372481336889164974134714013283018099565091354084263005640124246603862770719703573054722470086863068285815116342150689327182380499797749165599422704380253944639729145304791491099064057493156076981373714520634606949473, 16999730304730078253817608057972467347309223968496624296294968781316605440148409563011329841844262314146357841699028072349108904308417977727158661795088751574569482232520257575237485690201475478505913333557784829158773508924589344834125875828400628083793356503799521926680717206324504037691491546965239700027470441504714957539653468685572969246181396487877216267521187549795121184083468359258757946140192861965869509330741710040992538932823214070774019031529198127002431470028260248221159298260478349552980547430585921925972953125574098935759013232909510947861450758290172657746314751509889908440852993088278450756451)

    # Encrypt and decrypt
    encrypt_and_decrypt(data_to_encrypt, pub_keypair, priv_keypair)

    # Encrypt
    encrypted_data = rsa_mod_exp(int.from_bytes(data_to_encrypt, byteorder='big'), priv_keypair[0], priv_keypair[1])

    # Precompute values for Noir circuit
    final_e = get_final_e(encrypted_data, pub_keypair[1])
    print("final_e:", hex(final_e))
    quotient = get_sig_quotient(encrypted_data, pub_keypair[1], final_e)
    print("quotient:", hex(quotient))
    print()

    print_hex_as_noir_array('sig_bytes', hex(encrypted_data))
    print_hex_as_noir_array('pubkey_bytes', hex(pub_keypair[1]))
    print_hex_as_noir_array('final_e_bytes', hex(final_e))
    print_hex_as_noir_array('quotient_bytes', hex(quotient))
    print_hex_as_noir_array('expected', data_to_encrypt.rjust(49, b'\x00'))
    print()
    
    print(obj_to_toml({
        'sig': int_to_bytes(encrypted_data),
        'pubkey': int_to_bytes(pub_keypair[1]),
        'final_e': int_to_bytes(final_e),
        'quotient': int_to_bytes(quotient),
        'expected': data_to_encrypt.rjust(49, b'\x00')
    }))
    
if __name__ == "__main__": main()
