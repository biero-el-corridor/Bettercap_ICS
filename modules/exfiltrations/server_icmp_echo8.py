from scapy.all import *
import base64
import json
import hashid
import argparse 
chunck_list = []
separator = "\' \'" 

"""
TODO section 

- [X] parse the json output. 
- [ ] add to a json file. 
- [ ] see if we need to add more informationsto collect to add in contexte. 
- [ ] add argparse sections for the following 
    - [ ] interface
- [ ] think about a method to target only exfiltrar data containing packet. 
"""
parser = argparse.ArgumentParser()

parser.add_argument('-eth', '--eth' , help='add the listend interface name',type=str)

args = parser.parse_args()



############################################
####### START JSON FILE Handeling sections #
############################################



############################################
####### END JSON FILE Handeling sections #
############################################


############################################################
####### START retrive and checksum data handeling sections #
############################################################


# will tacke the md5 integrity between send message end the result data value
def integrity_check(decoded_data): 
    is_md5_intergity_ok = True
    # print(decoded_data)
    json_obj = json.loads(decoded_data)
        # Formater le JSON
    formatted_json = json.dumps(json_obj, indent=4)
    decoded_data = base64.b64decode(json_obj['DATA'])
    # print(decoded_data)
    # Afficher le JSON formaté
    try: 
        interity_md5_server_side = hashlib.md5(decoded_data).hexdigest()
    except:
        is_md5_intergity_ok = False    
    ## extract the 
    interity_md5_clinet_side =  ""
    try:
        # obligations de faire sa pk si un chiffre hexa et en dessous de 9 , il va étre convertie sans le zero defant 
        # se qui va crée un décalage dans le ash , donc il faut rajouter un zero devant tout les chiffre 
        for val in json_obj['MD5']: 
            val = hex(val)[2:]
            if val.isdigit() and int(val) < 9: 
                val = format(int(val), '02x')
                interity_md5_clinet_side=  interity_md5_clinet_side +  (str(val))
            else:
                interity_md5_clinet_side = interity_md5_clinet_side + str(val) #hex_string = ''.join(val)
    except:
        is_md5_intergity_ok = False   
    # Concaténer les valeurs hexadécimales
    #hex_string = ''.join(format(hex_values))

    # Afficher la chaîne hexadécimale concaténée

    if interity_md5_clinet_side == interity_md5_server_side : 
        print(is_md5_intergity_ok)
    return is_md5_intergity_ok, decoded_data

def data_handeling(decoded_data): 

    # Charger le JSON
    json_obj = json.loads(decoded_data)

    # Formater le JSON
    formatted_json = json.dumps(json_obj, indent=4)

    # Afficher le JSON formaté
    #print(formatted_json)


def icmp_handler(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        #print(f"ICMP request: {pkt[ICMP].payload}")
        a = pkt[ICMP].payload.load
        chunck = a.decode('utf-8')
        chunck_list.append(chunck)
        if chunck.endswith("\""):
            interity_md5_clinet_side = separator.join(chunck_list)
            additioned_chunk  = interity_md5_clinet_side.replace("\' \'", "")
            # wil print a oneliner of the receptioned code
            
            ##print("exfiltrer ", base64.b64decode(interity_md5_clinet_sideult).decode('utf-8'))
            
            # verify the integrity of the message send by compare the md5 hashe to the hashe data value.
            is_ok , data = integrity_check(base64.b64decode(additioned_chunk).decode('utf-8'))
            if is_ok == True: 
                """
                # extract the data value from the base payload
                # parse the extracte value and store it in a json file.
                decoded_data = additioned_chunk.decode('utf-8')  
                decoded_data = additioned_chunk['DATA'] 
                """
                print(data.decode('utf-8') )
            else:
                chunck_list.clear()
                        
            chunck_list.clear()


############################################################
####### END retrive and checksum data handeling sections   #
############################################################

if __name__ == "__main__":
    sniff(iface=args.eth, prn=icmp_handler)
    