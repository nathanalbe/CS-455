import struct


#unpack what we sent
def unpack_respose(data,original_id):
    # Header
    id   = int.from_bytes(data[0:2],  "big")
    flags = int.from_bytes(data[2:4],  "big")
    qd    = int.from_bytes(data[4:6],  "big")
    an    = int.from_bytes(data[6:8],  "big")
    ns    = int.from_bytes(data[8:10], "big")
    ar    = int.from_bytes(data[10:12],"big")


    if (id != original_id):
        print("Response ID does not match the query ID")
        return

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = (flags) & 0xF
    
    print("header.ID = ",original_id)
    print("header.QR = ",qr)
    print("header.OPCODE = ",opcode)
    print("header.AA = ",aa)
    print("header.TC = ",tc)
    print("header.RD = ",rd)
    print("header.RA = " ,ra)
    print("header. Z = ", z)
    print("header.RCODE = ",rcode)


    # Questions
    start = 12
    qname, start = qname_decoder(data, start)
    qtype = int.from_bytes(data[start:start+2],  "big")
    #A->1
    #AAAA->28
    #CNAME ->5
    start += 2
    qclass = int.from_bytes(data[start:start+2],  "big")
    start += 2
    
    
    
    print("question.QNAME = ",qname)
    print("question.QTYPE = ",qtype)
    print("question.QCLASS = ",qclass)

    # Answer
    
    for i in range(an):
        name, start = qname_decoder(data, start)
        rtype = int.from_bytes(data[start:start+2],"big")
        start += 2
        rclass = int.from_bytes(data[start:start+2],"big")
        start += 2
        ttl = int.from_bytes(data[start:start+4], "big")
        start += 4
        rdlength = int.from_bytes(data[start:start+2], "big")
        start += 2

        rdata, start = parse_rdata (data,start,rtype, rdlength) 

        type_str = {1: 'A', 28: 'AAAA', 5: 'CNAME'}.get(rtype, str(rtype))
        print("answer.NAME = ", name)
        print("answer.TYPE = ",rtype)
        print("answer.CLASS = ",rclass)
        print("answer.TTL = ",ttl)
        print("answer.RDATA = ",rdata)

    if ns > 0:
        for i in range(ns):
            name, start = qname_decoder(data, start)
            rtype = int.from_bytes(data[start:start+2], "big")
            start += 2
            rclass = int.from_bytes(data[start:start+2], "big")
            start += 2
            ttl = int.from_bytes(data[start:start+4], "big")
            start += 4
            rdlength = int.from_bytes(data[start:start+2], "big")
            start += 2
            
            rdata, start = parse_rdata(data, start, rtype, rdlength)
            
            type_str = {1: 'A', 28: 'AAAA', 5: 'CNAME'}.get(rtype, str(rtype))
            
            print("authority.NAME = ",name)
            print("authority.TYPE = ",rtype)
            print("authority.CLASS = ",rclass)
            print("authority.TTL = ", ttl)
            print("authority.RDATA = ",rdata)
    if ar > 0:
        for i in range(ar):
            name, start = qname_decoder(data, start)
            rtype = int.from_bytes(data[start:start+2], "big")
            start += 2
            rclass = int.from_bytes(data[start:start+2], "big")
            start += 2
            ttl = int.from_bytes(data[start:start+4], "big")
            start += 4
            rdlength = int.from_bytes(data[start:start+2], "big")
            start += 2
            
            rdata, start = parse_rdata(data, start, rtype, rdlength)
            
            type_str = {1: 'A', 28: 'AAAA', 5: 'CNAME'}.get(rtype, str(rtype))

            print("additional.NAME = ",name)
            print("additional.TYPE = ",rtype)
            print("additional.CLASS = ",rclass)
            print("additional.TTL = ", ttl)
            print("additional.RDATA = ",rdata)


        
    

    
def parse_rdata(data,start,rtype, rdlength):
    if rtype == 1:  # A record
        ip_parts = struct.unpack('!BBBB', data[start:start+4])
        ip_str = ""
        for i, part in enumerate(ip_parts):
            if i > 0:
                ip_str += "."
            ip_str += str(part)
        return ip_str, start + 4
        
    elif rtype == 28:  # AAAA record
        ip_parts = struct.unpack('!HHHHHHHH', data[start:start+16])
        ipv6 = ""
        for i, part in enumerate(ip_parts):
            if i > 0:
                ipv6 += ":"
            ipv6 += f"{part:04x}"
        return ipv6, start + 16
        
    elif rtype == 5:  # CNAME record
        cname, new_pos = qname_decoder(data, start)
        return cname, new_pos
        
    elif rtype == 2:  # NS record
        ns, new_pos = qname_decoder(data, start)
        return ns, new_pos
        
    else:
        return f"[Record type {rtype}, {rdlength} bytes]", start + rdlength



def qname_decoder(response: bytes, start: int):
    """
    Decode a DNS domain name at 'start' in 'response', supporting compression.
    Returns (decoded_name, next_start_in_original_stream).
    """
    labels = []
    jumped = False
    next_start = None

    while True:
        length_byte = response[start]

        # Compression pointer? (top two bits 11)
        if (length_byte & 0xC0) == 0xC0:
            ptr = ((length_byte & 0x3F) << 8) | response[start + 1]
            if not jumped:
                next_start = start + 2  # resume after pointer in the original stream
                jumped = True
            start = ptr                # jump to the pointed-to name
            continue

        # End of the name
        if length_byte == 0:
            if not jumped:
                next_start = start + 1  # consumed the 0x00 terminator in-place
            break

        # Normal label
        start += 1
        labels.append(response[start:start + length_byte].decode("ascii"))
        start += length_byte

    return ".".join(labels), next_start
            
        





    '''
    def main():
    print("Preparing DNS query..")
    query_data, query_id = Query_user_input()
    
    print("Contacting DNS server..")
    print("Sending DNS query..")
    
    response = send_data(query_data)
    
    if response:
        unpack_response(response, query_id)
    else:
        print("ERROR: No response received from DNS server")
    '''