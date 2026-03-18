import sys
import struct
import argparse

#Modify the SID hex value retrieved from query 
def prepare_sid(sid):
    hex_string = bytes.fromhex(sid[2:])
    mod_sid = sid_to_str(hex_string)
    domain_sid_data = mod_sid.split('-')[:7]
    domain_sid = '-'.join(domain_sid_data) + "-"

    print(domain_sid+"\n")
    return domain_sid

#Build out the SID string
def sid_to_str(sid):
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]

    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]
    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert MSSQL SID hex to string format and modify it.')
    parser.add_argument('sid', type=str, help='The SID hex value retrieved from MSSQL query (e.g., 0x010500000000000515000000b3c9a1d3e5f4d2a3b4c5d6e7f8090a0b0c0d0e0f)')
    args = parser.parse_args()

    prepare_sid(args.sid)
