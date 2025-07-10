#Import Libraries
import urllib.request #Http Get and POST Library
import urllib.parse   #Http formating Library
import json           #Json Library
import hashlib        #Hashing Library for sha256
import time           #Time Library

server_a = "http://node-a.example.com"  #Defining ledger A's Server Address
server_b = "http://node-b.example.com"  #Defining ledger B's Server Address
server_c = "http://node-c.example.com"  #Defining ledger C's Server Address

url_new_block    = "/new.php"         #Defining ledger index and previous hash location
url_create_block = "/create_new.php"  #Defining create new block location
url_get_block    = "/get_block.php"   #Defining get block location
url_ledger_hash  = "/hash_chain.php"  #Defining ledger hash get location

proof_number=4      #Defining proof length, increase to make proof harder
proof_value="0000"  #Defining proof value, must have the same amount of digits as the proof value

#-------------------------------------------------------------------------------------------------------------------------------------
#Finds the corrent proof for a new Block
def New_proof_of_work(last_hash):
    guess_hash="" #Defines variable guess_hash to ""
    proof=0       #Defines variable proof to 0
    while(guess_hash[:proof_number] != proof_value):   #Loops while guess_hash's first n digits is not equal to proof value, n digits is equal the the value that is stored in proof_number
        proof += 1                                     #Increments proof by 1
        guess = (str(last_hash)+str(proof)).encode()         #Builds a bytes object from the string that includes last_hash and proof
        guess_hash = hashlib.sha256(guess).hexdigest() #Hashs the bytes object using sha256
    return proof                                           #Once the while statment is no longer true, meaning we have found the corret proof value, it will return the proof value.

#-------------------------------------------------------------------------------------------------------------------------------------
#Creates a New Block
def New_Block(data):
    #print("CREATE NEW BLOCK-----------") #Debug
    block_server_count=0     #Defines block_server_count to 0
    index_a =-1              #Defines index_a to -1
    previous_hash_a=""       #Defines previous_hash_a to ""
    index_b =-1              #Defines index_b to -1
    previous_hash_b=""       #Defines previous_hash_b to ""
    index_c =-1              #Defines index_c to -1
    previous_hash_c=""       #Defines previous_hash_c to ""
    decide_index=-1          #Defines decide_index to -1
    decide_previous_hash=""  #Defines decide_previous_hash to ""
    #Gets block id and previous_hash from Server A
    try:
        with urllib.request.urlopen(server_a + url_new_block) as f: #Submits HTTP GET
            jdata = json.loads(f.read().decode('utf-8')) #Decodes json that server returned
            index_a=jdata['id']                          #Saves the id from the server to index_a
            previous_hash_a=jdata['previous_hash']       #Saves the previous_hash_c from the server to previous_hash_a
    except:
        print("Error with A Get") #Prints if there is an error
    #Gets block id and previous_hash from Server B
    try:
        with urllib.request.urlopen(server_b + url_new_block) as f: #Submits HTTP GET
            jdata = json.loads(f.read().decode('utf-8')) #Decodes json that server returned
            index_b=jdata['id']                          #Saves the id from the server to index_b
            previous_hash_b=jdata['previous_hash']       #Saves the previous_hash_c from the server to previous_hash_b
    except:
        print("Error with B Get") #Prints if there is an error
    #Gets block id and previous_hash from Server C
    try:
        with urllib.request.urlopen(server_c + url_new_block) as f: #Submits HTTP GET
            jdata = json.loads(f.read().decode('utf-8')) #Decodes json that server returned
            index_c=jdata['id']                          #Saves the id from the server to index_c
            previous_hash_c=jdata['previous_hash']       #Saves the previous_hash_c from the server to previous_hash_c
    except:
        print("Error with C Get") #Prints if there is an error

    #Voting System for block id
    if(index_a == index_b and index_a == index_c): #Checks to see if the index from server A, B and C are equal
        decide_index=index_a                       #Sets decide_index to index_a
    else:
        if(index_a == index_b):     #Checks to see if the index from server A and B are equal
            decide_index=index_a    #Sets decide_index to index_a
        if(index_a == index_c):     #Checks to see if the index from server A and C are equal
            decide_index=index_a    #Sets decide_index to index_a
        if(index_b == index_c):     #Checks to see if the index from server B and C are equal
            decide_index=index_b    #Sets decide_index to index_b

    if(decide_index==-1): #If there is no vailed block id
        return 0,0,0      #Then Return 0,0,0 and stop function here.

    #Voting System for block Previous Hash
    if(previous_hash_a == previous_hash_b and previous_hash_a == previous_hash_c):  #Checks to see if the previous_hash from server A, B and C are equal
        decide_previous_hash=previous_hash_a                                        #Sets decide_previous_hash to previous_hash_a
    else:
        if(previous_hash_a == previous_hash_b):     #Checks to see if the previous_hash from server A and B are equal
            decide_previous_hash=previous_hash_a    #Sets decide_previous_hash to previous_hash_a
        if(previous_hash_a == previous_hash_c):     #Checks to see if the previous_hash from server A and B are equal
            decide_previous_hash=previous_hash_a    #Sets decide_previous_hash to previous_hash_a
        if(previous_hash_b == previous_hash_c):     #Checks to see if the previous_hash from server B and C are equal
            decide_previous_hash=previous_hash_b    #Sets decide_previous_hash to previous_hash_b

    proof = New_proof_of_work(decide_previous_hash) #Gets proof for block
    block = {                                       #Creats Block Object
        'id': decide_index,                         #Adds id to block Object
        'timestamp': str(time.time()),              #Adds current timestamp to block Object
        'data': data,                               #Adds data to block Object
        'proof': proof,                             #Adds proof to block Object
        'previous_hash': decide_previous_hash       #Adds previous_hash to block Object
    }
    block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
    block_hash = hashlib.sha256(block_string).hexdigest()                            #Hashs json string using sha256 and converts output to hex
    block['block_hash']=block_hash                                                   #Adds block hash to block Object
    #Parse the block ready for the HTTP POST
    data = urllib.parse.urlencode({'id': block['id'], 'hash': block['block_hash'], 'timestamp': block['timestamp'], 'proof': block['proof'], 'data': block['data'], 'previous_hash': block['previous_hash']})
    data = data.encode('ascii')
    #print(block_string) #Debug
    #Submits block to Server A
    try:
        with urllib.request.urlopen(server_a + url_create_block, data) as f: #Submits HTTP POST
            jdata = json.loads(f.read().decode('utf-8'))   #Decodes json that server returned
            if(jdata['status']=="Block_Created"):          #Checks if server successfully created the block
                block_server_count = block_server_count+1  #Increments block_server_count if block successfully created on server A
    except:
        print("Error with A Create") #Prints if there is an error
    #Submits block to Server B
    try:
        with urllib.request.urlopen(server_b + url_create_block, data) as f: #Submits HTTP POST
            jdata = json.loads(f.read().decode('utf-8'))   #Decodes json that server returned
            if(jdata['status']=="Block_Created"):          #Checks if server successfully created the block
                block_server_count = block_server_count+1  #Increments block_server_count if block successfully created on server B
    except:
        print("Error with A Create") #Prints if there is an error
    #Submits block to Server C
    try:
        with urllib.request.urlopen(server_c + url_create_block, data) as f: #Submits HTTP POST
            jdata = json.loads(f.read().decode('utf-8'))   #Decodes json that server returned
            if(jdata['status']=="Block_Created"):          #Checks if server successfully created the block
                block_server_count = block_server_count+1  #Increments block_server_count if block successfully created on server C
    except:
        print("Error with A Create") #Prints if there is an error

    return block['id'], block_hash, block_server_count #Returns block id, block hash, number of servers that accepted the new block
#-------------------------------------------------------------------------------------------------------------------------------------
#This Functions gets a hash of each ledger and compares them to each other.
def Get_Chain_Hash():
    #print("GET Chain HASH-----------")
    hash_a = "" #Defines variable hash_a to ""
    hash_b = "" #Defines variable hash_b to ""
    hash_c = "" #Defines variable hash_c to ""
    try:
        with urllib.request.urlopen(server_a + url_ledger_hash) as f: #Does the HTTP request
            jdata = json.loads(f.read().decode('utf-8')) #Loads HTTP results into a json object
            hash_a=jdata['hash']                         #Defines variable hash_c to the hash it receives in the HTTP request.
    except:                                              #Runs if Error occurs
        print("Error with A Get")                        #Prints "Error with A Get" to the console
    try:
        with urllib.request.urlopen(server_b + url_ledger_hash) as f: #Does the HTTP request
            jdata = json.loads(f.read().decode('utf-8')) #Loads HTTP results into a json object
            hash_b=jdata['hash']                         #Defines variable hash_c to the hash it receives in the HTTP request.
    except:                                              #Runs if Error occurs
        print("Error with B Get")                        #Prints "Error with B Get" to the console
    try:
        with urllib.request.urlopen(server_c + url_ledger_hash) as f: #Does the HTTP request
            jdata = json.loads(f.read().decode('utf-8')) #Loads HTTP results into a json object
            hash_c=jdata['hash']                         #Defines variable hash_c to the hash it receives in the HTTP request.
    except:                                              #Runs if Error occurs
        print("Error with C Get")                        #Prints "Error with C Get" to the console

    if(hash_a == hash_b and hash_a == hash_c): #Checks to see if ledger A, B and C match.
        return 1,1,1                           #Returns 1,1,1 if ledger A, B and C match.
    else:
        if(hash_a == hash_b):   #Checks to see if ledger A and B match.
            return 1,1,0        #Returns 1,1,0 if ledger A and B match.
        elif(hash_a == hash_c): #Checks to see if ledger A and C match.
           return 1,0,1         #Returns 1,0,1 if ledger A and C match.
        elif(hash_b == hash_c): #Checks to see if ledger B and C match.
            return 0,1,1        #Returns 0,1,1 if ledger B and C match.
        else:                   #
            return 0,0,0        #Returns 0,0,0 if no two ledgers match.
#-------------------------------------------------------------------------------------------------------------------------------------
#This Functions needs the Block id/index and will return the data from that block as well as the confidence.
def Get_Block(block_id):
    #print("GET BLOCK-----------")
    hash_a = 0  #Defines variable hash_a to 0, hash equaling 0 would mean the chain is invalid and this should be changed further down in the function
    hash_b = 0  #Defines variable hash_b to 0, hash equaling 0 would mean the chain is invalid and this should be changed further down in the function
    hash_c = 0  #Defines variable hash_c to 0, hash equaling 0 would mean the chain is invalid and this should be changed further down in the function
    data_a = "" #Defines variable data_a to ""
    data_b = "" #Defines variable data_b to ""
    data_c = "" #Defines variable data_c to ""
    id_a   = -1 #Defines variable id_a to -1, id equaling -1 is invalid and this should be changed further down in the function
    id_b   = -1 #Defines variable id_b to -1, id equaling -1 is invalid and this should be changed further down in the function
    id_c   = -1 #Defines variable id_c to -1, id equaling -1 is invalid and this should be changed further down in the function
    
    data = urllib.parse.urlencode({'id': block_id}) #Parses the id so that it ready for the HTTP POST.
    data = data.encode('ascii')                     #Coverts data to ascii if it is not already.
    
    #Get Block from  Server A
    try:
        with urllib.request.urlopen(server_a + url_get_block, data) as f:
            jdata = json.loads(f.read().decode('utf-8'))        #Loads HTTP results into a json object
            if(len(jdata) == 3):                                #Checks if json object has 3 elements in it.
                #print("A: Can Vaildate Block")                 #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                jdata2 = json.loads(jdata[2])                   #Loads element 3 into jdata2
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                next_block_hash=jdata2['hash']                  #Defines next_block_hash and stores the (current block+1) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.s
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_a = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash1                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata2['proof']                                                            #Sets last hash as (current block-0) genarated hash
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash2 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash2 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block+1), this is going to be used to recreate the block
                'id': jdata2['id'],
                'timestamp': jdata2['timestamp'],
                'data': jdata2['data'],
                'proof': jdata2['proof'],
                'previous_hash': block_hash1,
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash2 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and next_block_hash==block_hash2 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value and guess_hash2[:proof_number] == proof_value):
                    hash_a=3                 #Sets hash_a to 3
                    data_a=jdata1['data']    #Sets data_a to block data
                    #print("A: Chain Valid") #Debug
                else:
                    hash_a=0                     #Sets hash_a to 0
                    data_a=""                    #Sets data_a to ""
                    #print("A: Chain NOT Valid") #Debug
            
            
            elif(len(jdata) == 2):                              #Checks if json object has 2 elements in it.
                #print("A: Can Only Vaildate Chain")            #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_a = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value):
                    hash_a=2                        #Sets hash_a to 2
                    data_a=jdata1['data']           #Sets data_a to block data
                    #print("A: Chain Valid with 2") #Debug
                else:
                    hash_a=0                            #Sets hash_a to 0
                    data_a=""                           #Sets data_a to ""
                    #print("A: Chain NOT Valid with 2") #Debug
            else:
                hash_a=0
                data_a=""
                print("Block Doesn't Exist")
    except:
        print("Error with A Get")

    #Get Block from  Server B
    try:
        with urllib.request.urlopen(server_b + url_get_block, data) as f:
            jdata = json.loads(f.read().decode('utf-8'))        #Loads HTTP results into a json object
            if(len(jdata) == 3):                                #Checks if json object has 3 elements in it.
                #print("B: Can Vaildate Block")                 #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                jdata2 = json.loads(jdata[2])                   #Loads element 3 into jdata2
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                next_block_hash=jdata2['hash']                  #Defines next_block_hash and stores the (current block+1) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_b = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash1                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata2['proof']                                                            #Sets last hash as (current block-0) genarated hash
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash2 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash2 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block+1), this is going to be used to recreate the block
                'id': jdata2['id'],
                'timestamp': jdata2['timestamp'],
                'data': jdata2['data'],
                'proof': jdata2['proof'],
                'previous_hash': block_hash1,
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash2 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and next_block_hash==block_hash2 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value and guess_hash2[:proof_number] == proof_value):
                    hash_b=3                 #Sets hash_b to 3
                    data_b=jdata1['data']    #Sets data_b to block data
                    #print("B: Chain Valid") #Debug
                else:
                    hash_b=0                     #Sets hash_b to 0
                    data_b=""                    #Sets data_b to ""
                    #print("B: Chain NOT Valid") #Debug
            
            
            elif(len(jdata) == 2):                              #Checks if json object has 2 elements in it.
                #print("B: Can Only Vaildate Chain")            #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_b = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value):
                    hash_b=2                        #Sets hash_b to 2
                    data_b=jdata1['data']           #Sets data_b to block data
                    #print("B: Chain Valid with 2") #Debug
                else:
                    hash_b=0                            #Sets hash_b to 0
                    data_b=""                           #Sets data_b to ""
                    #print("B: Chain NOT Valid with 2") #Debug
            else:
                hash_b=0
                data_b=""
                print("Block Doesn't Exist")
    except:
        print("Error with B Get")

    #Get Block from  Server C
    try:
        with urllib.request.urlopen(server_c + url_get_block, data) as f:
            jdata = json.loads(f.read().decode('utf-8'))        #Loads HTTP results into a json object
            if(len(jdata) == 3):                                #Checks if json object has 3 elements in it.
                #print("C: Can Vaildate Block")                  #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                jdata2 = json.loads(jdata[2])                   #Loads element 3 into jdata2
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                next_block_hash=jdata2['hash']                  #Defines next_block_hash and stores the (current block+1) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_c = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash1                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata2['proof']                                                            #Sets last hash as (current block-0) genarated hash
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash2 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash2 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block+1), this is going to be used to recreate the block
                'id': jdata2['id'],
                'timestamp': jdata2['timestamp'],
                'data': jdata2['data'],
                'proof': jdata2['proof'],
                'previous_hash': block_hash1,
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash2 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and next_block_hash==block_hash2 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value and guess_hash2[:proof_number] == proof_value):
                    hash_c=3                 #Sets hash_c to 2
                    data_c=jdata1['data']    #Sets data_c to block data
                    #print("C: Chain Valid") #Debug
                else:
                    hash_c=0                     #Sets hash_c to 0
                    data_c=""                    #Sets data_c to ""
                    #print("C: Chain NOT Valid") #Debug
 

            elif(len(jdata) == 2):                              #Checks if json object has 2 elements in it.
                #print("C: Can Only Vaildate Chain")            #Debug
                jdata0 = json.loads(jdata[0])                   #Loads element 1 into jdata0
                jdata1 = json.loads(jdata[1])                   #Loads element 2 into jdata1
                previous_block_hash=jdata0['hash']              #Defines previous_block_hash and stores the (current block-1) hash in it.
                current_block_hash=jdata1['hash']               #Defines current_block_hash and stores the (current block-0) hash in it.
                last_hash=jdata0['previous_hash']               #Defines last_hash and stores the (current block-2) hash in it.
                proof=jdata0['proof']                           #Defines proof and stores the (current block-1) proof in it.
                guess = (str(last_hash)+str(proof)).encode()    #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash0 = hashlib.sha256(guess).hexdigest() #Defines guess_hash0 and stores the hashed version of guess in it.
                block = {                                       #Defines (current block-1), this is going to be used to recreate the block
                'id': jdata0['id'],
                'timestamp': jdata0['timestamp'],
                'data': jdata0['data'],
                'proof': jdata0['proof'],
                'previous_hash': jdata0['previous_hash'],
                }
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash0 = hashlib.sha256(block_string).hexdigest()                           #Hashs json string using sha256 and converts output to hex
                last_hash=block_hash0                                                            #Sets last hash as (current block-1) genarated hash
                proof=jdata1['proof']                                                            #Defines proof and stores the (current block-0) proof in it.
                guess = (str(last_hash)+str(proof)).encode()                                     #Defines guess and genurates the proof string from last_hash and proof.
                guess_hash1 = hashlib.sha256(guess).hexdigest()                                  #Defines guess_hash1 and stores the hashed version of guess in it.
                block = {                                                                        #Defines (current block-0), this is going to be used to recreate the block
                'id': jdata1['id'],
                'timestamp': jdata1['timestamp'],
                'data': jdata1['data'],
                'proof': jdata1['proof'],
                'previous_hash': block_hash0,
                }
                id_c = jdata1['id']                                                              #Defines id_a and stores the (current block-0) id in it.
                block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode() #Converts block Object to a json string with keys in alphabetical order
                block_hash1 = hashlib.sha256(block_string).hexdigest()
                
                #Checks to see if the hashs and proofs match
                if(previous_block_hash==block_hash0 and current_block_hash==block_hash1 and guess_hash0[:proof_number] == proof_value and guess_hash1[:proof_number] == proof_value):
                    hash_c=2                        #Sets hash_c to 2
                    data_c=jdata1['data']           #Sets data_c to to block data
                    #print("C: Chain Valid with 2") #Debug
                else:
                    hash_c=0                            #Sets hash_c to 2
                    data_c=""                           #Sets data_c to ""
                    #print("C: Chain NOT Valid with 2") #Debug
            else:
                hash_c=0
                data_c=""
                print("Block Doesn't Exist")
    except:
        print("Error with C Get")


    if(hash_a==hash_b and hash_a==hash_c and hash_a >=2 and data_a==data_b and data_a == data_c and id_a==id_b and id_a==id_c and id_a != -1): #Checks to see if the hash status, data and id from ledger A, B and C match, also that the id is not equal to -1
        #print("Data Valid")                                                                    #Debug
        return id_a, data_a, hash_a, 3                                                          #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
    else:
        if(hash_a == hash_b and data_a==data_b and hash_a >=2 and id_a==id_b and id_a != -1):   #Checks to see if the hash status, data and id from ledger A and B match, also that the id is not equal to -1
            return id_a, data_a, hash_a, 2                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        elif(hash_a == hash_c and data_a==data_c and hash_a >=2 and id_a==id_c and id_a != -1): #Checks to see if the hash status, data and id from ledger A and C match, also that the id is not equal to -1
            return id_a, data_a, hash_a, 2                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        elif(hash_b == hash_c and data_b==data_c and hash_b >=2 and id_b==id_c and id_b != -1): #Checks to see if the hash status, data and id from ledger B and C match, also that the id is not equal to -1
            return id_b, data_b, hash_b, 2                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        elif(hash_a >=2 and id_a != -1):                                                        #Checks to see if the hash status is greater or equal to 2 and that the id is not equal to -1 from ledger A
            return id_a, data_a, hash_a, 1                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        elif(hash_b >=2 and id_b != -1):                                                        #Checks to see if the hash status is greater or equal to 2 and that the id is not equal to -1 from ledger B
            return id_b, data_b, hash_b, 1                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        elif(hash_c >=2 and id_c != -1):                                                        #Checks to see if the hash status is greater or equal to 2 and that the id is not equal to -1 from ledger C
            return id_c, data_c, hash_c, 1                                                      #Returns (Block id, Block Data, Hash Status, number of ledgers that validated the data)
        else:
            #print("Data Missmatch")                                                            #Debug
            return -1, False, 0, 0                                                              #Returns (-1, False, 0, 0) if no valid chain is found
#-------------------------------------------------------------------------------------------------------------------------------------
print(New_Block("DATA:1"))
block2=New_Block("DATA:5")
#block3=New_Block("DATA:3")
#block4=New_Block("Alfa")

print(Get_Chain_Hash())

print(Get_Block(New_Block("DATA:test")[0]))
#print(Get_Block(block2[0]))
#print(Get_Block(block4[0]))
print(Get_Block(2))

print(Get_Block(8))



