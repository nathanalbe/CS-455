
import sys
import random
import struct

def encode_hostname(hostname):
    """
    Encodes a hostname into its DNS QName format. 
    """
    parts = hostname.split('.')
    encoded = b''
    for part in parts:
        if part:
            encoded += bytes([len(part)]) + part.encode('ascii')
    encoded += b'\x00'  # End of the QName, null terminator for root
    print(encoded)
    return encoded

### get an input form the user
    #my-dns-client <hostname> <query-type>
def Query_user_input():
    if (len(sys.argv) < 3):
        #invalid
        sys.exit(1)
    host_name = sys.argv[1]
    query_type = sys.argv[2]

    if (query_type not in ["A","AAAA","CNAME"]):
        print("Query Name must be A or AAAA or CNAME")
        sys.exit(1)
    
    ### Filling the Header

    #ID = 16 bit randomly generated 
        #16 bit = 2^16 -> 65535
    header_id = random.randint (0,65535)
    print("HEADER ID = ", header_id)

    #QR should be 0 (bit 0)
    header_qr = 0

    #opcode should be 0 (bit 1-4)
    header_opcode = 0

    AA = 0
    TC = 0

    #RD set it to 1 (bit 7)
    header_rd = 1

    RA = 0
    Z = 0
    RCODE = 0

    #make our 16 bit
    header_flag = (header_qr << 15) | (header_opcode << 11) | (AA << 10)| (header_rd << 8) | (TC << 9) | (header_rd << 8) | (RA << 7) | (Z << 4) | RCODE

    #QDCOUNT should be 1 (16 bit)
    QDCOUNT = 1

    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    dns_header = struct.pack("!HHHHHH", header_id, header_flag, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    ##Question

    #Generate QName
    QNAME = encode_hostname(host_name) # -> QNAME

    #Qclass
    QCLASS = 1
    
    #qtype
    if (query_type == "AAAA"):
        header_Qtype = 28
    elif (query_type == "A"):
        header_Qtype =   1
    else:
        header_Qtype = 5
    
    question = QNAME + struct.pack("!HH",header_Qtype,QCLASS)

    dns_query = dns_header + question, header_id

    return dns_query


print(Query_user_input())

