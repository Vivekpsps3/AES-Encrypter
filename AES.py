import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []   

class AES():
    def __init__(self, keyfile:str) -> None:
        # Read the key from the file
        with open(keyfile, 'r') as file:
            key = file.read()
        # Convert the key into a BitVector
        key_bv = BitVector(textstring = key)
        # Generate the key schedule
        key_words = gen_key_schedule_256(key_bv)
        # Generate the round keys
        self.round_keys = gen_round_keys(key_words)
        pass

    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        # Read the plaintext from the file
        bv = BitVector(filename = plaintext)
        FILEOUT = open(ciphertext, 'w')
        output = BitVector(size = 0)
        round_keys = self.round_keys

        # while the bitvector has more bits to read
        while bv.more_to_read:
            
            # read 128 bits from the bitvector
            # if the bitvector has less than 128 bits, pad it with 0s
            bitvec = bv.read_bits_from_file(128)
            if (bitvec.length() < 128):
                bitvec.pad_from_right(128 - bitvec.length())
            
            #perform step 1 of the encryption algorithm
            # XOR the bitvec with the first round key
            bitvec = bitvec ^ round_keys[0]
            state_array = gen_state_array(bitvec)

            #perform steps 2-13 of the encryption algorithm
            # for each round key
            # perform the sub bytes, shift rows, mix columns, and add round key operations
            for i in range(1,14):
                state_array = sub_bytes(state_array)
                state_array = shift_rows(state_array)
                state_array = mix_columns(state_array)
                state_array = add_round_key(state_array, round_keys[i])
                state_array = gen_state_array(state_array)
            #perform step 14 of the encryption algorithm
            # for the last round key
            # perform the sub bytes, shift rows, and add round key operations
            state_array = sub_bytes(state_array)
            state_array = shift_rows(state_array)
            state_array = add_round_key(state_array, round_keys[14])
            output += state_array
        
        # write the output to the file
        output = output.get_bitvector_in_hex()
        FILEOUT.write(output)
        FILEOUT.close()
        
    def decrypt(self, ciphertext:str, decrypted:str) -> None:

        # Read the ciphertext from the file
        FILEIN = open(ciphertext, 'r')
        ciphertext = FILEIN.read()
        FILEIN.close()
        bv = BitVector(hexstring = ciphertext)

        # Initialize the counter
        counter = 0

        #bv = BitVector(filename = ciphertext)
        # open the output file and set up vars
        FILEOUT = open(decrypted, 'wb')
        output = BitVector(size = 0)
        round_keys = self.round_keys
        round_keys = round_keys[::-1]

        # while (bv.more_to_read):
        #     bitvec = bv.read_bits_from_file(128)

        # while the bitvector has more bits to read
        while (bv.length() > counter):
            # read 128 bits from the bitvector
            bitvec = bv[counter:counter+128]

            #perform step 1 of the decryption algorithm
            # XOR the bitvec with the first round key
            bitvec = bitvec ^ round_keys[0]
            # convert the bitvec into a 4x4 state array
            state_array = gen_state_array(bitvec)

            #perform steps 2-13 of the decryption algorithm
            # for each round key
            # perform the inverse shift rows, inverse sub bytes, add round key, and inverse mix columns operations
            for i in range(1,14):
                state_array = inv_shift_rows(state_array)
                state_array = inv_sub_bytes(state_array)
                state_array = add_round_key(state_array, round_keys[i])
                state_array = gen_state_array(state_array)
                state_array = inv_mix_columns(state_array)
            #perform step 14 of the decryption algorithm
            # for the last round key
            # perform the inverse shift rows, inverse sub bytes, and add round key operations
            state_array = inv_shift_rows(state_array)
            state_array = inv_sub_bytes(state_array)
            state_array = add_round_key(state_array, round_keys[14])

            # convert the state array into a bitvector and append it to the output
            output += state_array
            counter += 128

        # write the output to the file
        output.write_to_file(FILEOUT)
        FILEOUT.close()
    
    def ctr_aes_image(self, iv, image_file, enc_image):
        """
        Encrypts the image using AES in CTR mode.
        """
        round_keys = self.round_keys
        headers_list = []

        FILEIN = open(image_file, 'rb')
        FILEOUT = open(enc_image, 'wb')

        for i in range(3):
            temp_var = FILEIN.readline()
            FILEOUT.write(temp_var)
            headers_list.append(temp_var)
        
        FILEIN.close()
        header = b''.join(headers_list)
        header_bv = BitVector(rawbytes = header)

        bv = BitVector(filename = image_file)
        header_bits_length = header_bv.length()
        bv.read_bits_from_file(header_bits_length)

        while(bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            if (bitvec.length() < 128):
                bitvec.pad_from_right(128 - bitvec.length())
            
            #block_encryption starts here
            enc_block = block_encrypt(iv, round_keys)
            block_encrypted = enc_block ^ bitvec
            block_encrypted.write_to_file(FILEOUT)
            iv = BitVector(intVal = iv.int_val() + 1, size = 128)

        FILEOUT.close()
    
    def x931(self , v0 , dt , totalNum , outfile):
        """
        Inputs:
        v0: 128-bit seed value
        dt: 128-bit date/time value
        totalNum: Total number of pseudo-random numbers to generate
        outfile: The file to write the pseudo-random numbers to
        """
        round_keys = self.round_keys
        rand_num_list = []

        encoder = block_encrypt(dt, round_keys)
        for i in range(totalNum):
            rand_num = block_encrypt(encoder^v0, round_keys)
            rand_num_list.append(rand_num)
            v0 = block_encrypt(encoder^rand_num, round_keys)

        with open(outfile, 'w') as file:
            for num in rand_num_list:
                file.write(str(num.int_val()))
                file.write("\n")
        
def block_encrypt(bitvec, round_keys):
    """
    Encrypts the block using AES in CTR mode.
    """
    bitvec = bitvec ^ round_keys[0]
    state_array = gen_state_array(bitvec)

    #perform steps 2-13 of the encryption algorithm
    # for each round key
    # perform the sub bytes, shift rows, mix columns, and add round key operations
    for i in range(1,14):
        state_array = sub_bytes(state_array)
        state_array = shift_rows(state_array)
        state_array = mix_columns(state_array)
        state_array = add_round_key(state_array, round_keys[i])
        state_array = gen_state_array(state_array)
    
    #perform step 14 of the encryption algorithm
    # for the last round key
    # perform the sub bytes, shift rows, and add round key operations
    state_array = sub_bytes(state_array)
    state_array = shift_rows(state_array)
    state_array = add_round_key(state_array, round_keys[14])

    return state_array

def gen_round_keys(key_words):
    key_schedule = []
    #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        if word_index % 4 == 0: continue
        key_schedule.append(keyword_in_ints)
    #num_rounds is always 14 for 256-bit AES
    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
    return round_keys

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

def gen_key_schedule_256(key_bv):
    genTables()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, subBytesTable)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 subBytesTable[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_state_array(bitvec):
    # Convert the bitvec into a 4x4 state array

    # First we create a 4x4 array of ints:
    state_array = [[0 for i in range(4)] for j in range(4)]

    # Next we populate the state_array:
    for i in range(4):
        for j in range(4):
            # 32*i+8*j:32*i+8*j+8 is the range of bits for the j-th byte of the i-th word
            state_array[j][i] = bitvec[32*i+8*j:32*i+8*j+8].int_val()

    return state_array

def sub_bytes(state_array):
    # For the encryption SBox:
    # take the input from the state_array and return the substitute value from the subBytesTable
    for i in range(4):
        for j in range(4):
            state_array[i][j] = subBytesTable[state_array[i][j]]
    return state_array

def inv_sub_bytes(state_array):
    # For the decryption SBox:
    # take the input from the state_array and return the substitute value from the invSubBytesTable
    for i in range(4):
        for j in range(4):
            state_array[i][j] = invSubBytesTable[state_array[i][j]]
    return state_array

def shift_rows(state_array):
    # Shift the second row 1 to the left, the third row 2 to the left, and the fourth row 3 to the left
    state_array[1] = state_array[1][1:] + state_array[1][:1]
    state_array[2] = state_array[2][2:] + state_array[2][:2]
    state_array[3] = state_array[3][3:] + state_array[3][:3]
    return state_array

def inv_shift_rows(state_array):
    # Shift the second row 1 to the right, the third row 2 to the right, and the fourth row 3 to the right

    state_array[1] = state_array[1][3:] + state_array[1][:3]
    state_array[2] = state_array[2][2:] + state_array[2][:2]
    state_array[3] = state_array[3][1:] + state_array[3][:1]
    return state_array

def mix_columns(state_array):
    # First we convert the state_array into a 4x4 matrix of bvs:
    state_array = [[BitVector(intVal = state_array[j][i], size=8) for i in range(4)] for j in range(4)]
    
    # next we make an intermediary 4x4 matrix
    mix_col = [[0 for i in range(4)] for j in range(4)]

    # next we perform the mixColumns operation:
    for i in range(4):
        mix_col[0][i] = (state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ 
                         state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ 
                         state_array[2][i] ^ 
                         state_array[3][i])
        mix_col[1][i] = (state_array[0][i] ^ 
                         state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ 
                         state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ 
                         state_array[3][i])
        mix_col[2][i] = state_array[0][i] ^ state_array[1][i] ^ state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8) ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8)
        mix_col[3][i] = state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x03), AES_modulus, 8) ^ state_array[1][i] ^ state_array[2][i] ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    
    # Finally, we convert the state_array back into a 4x4 matrix of ints:
    for i in range(4):
        for j in range(4):
            state_array[i][j] = mix_col[i][j].int_val()
    
    # and we return the state array
    return state_array

def inv_mix_columns(state_array):

    # First we convert the state_array into a 4x4 matrix of bvs:    
    state_array = [[BitVector(intVal = state_array[j][i], size=8) for i in range(4)] for j in range(4)]
    
    # next we make a deep copy of the state_array and store it in mix_col:
    mix_col = [[0 for i in range(4)] for j in range(4)]

    # next we perform the invMixColumns operation:
    for i in range(4):
        mix_col[0][i] = state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8)
        mix_col[1][i] = state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8)
        mix_col[2][i] = state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8) ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8)
        mix_col[3][i] = state_array[0][i].gf_multiply_modular(BitVector(intVal = 0x0b), AES_modulus, 8) ^ state_array[1][i].gf_multiply_modular(BitVector(intVal = 0x0d), AES_modulus, 8) ^ state_array[2][i].gf_multiply_modular(BitVector(intVal = 0x09), AES_modulus, 8) ^ state_array[3][i].gf_multiply_modular(BitVector(intVal = 0x0e), AES_modulus, 8)
    
    # Finally, we convert the state_array back into a 4x4 matrix of ints:
    for i in range(4):
        for j in range(4):
            state_array[i][j] = mix_col[i][j].int_val()
    
    # and return the state_array:
    return state_array

def get_bv_from_state_array(state_array):
    """
    Converts a 4x4 state array into a BitVector.

    Args:
        state_array (list): The 4x4 state array.

    Returns:
        BitVector: The BitVector representation of the state array.
    """
    bv = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            val = BitVector(intVal = state_array[j][i], size=8)
            if len(val) < 8:
                val.pad_from_left(8-len(val))
            bv += val
    return bv

def add_round_key(state_array, round_key):
    """
    Adds the round key to the state array using bitwise XOR.

    Args:
        state_array (list of lists of ints): The state array.
        round_key (bv): The round key.

    Returns:
        bv: The result of adding the round key to the state array.
    """
    state_array = get_bv_from_state_array(state_array)
    state_array ^= round_key
    return state_array

if __name__ == "__main__":
    # Check for correct number of CLI arguments
    if len(sys.argv) != 5:
        sys.exit("Incorrect number of CLI arguments. Please use -e or -d as the first argument, the input file as the second argument, the key file as the third argument, and the output file as the fourth argument.")
    
    # Get the CLI arguments
    task = sys.argv[1]
    input_file = sys.argv[2]
    key_file = sys.argv[3]
    output_file = sys.argv[4]

    # Create an AES object
    cipher = AES(keyfile=key_file)

    # Encrypt or decrypt based on the CLI argument
    if task == "-e":
        cipher.encrypt(plaintext = input_file, ciphertext = output_file)
    elif task == "-d":
        cipher.decrypt(ciphertext = input_file, decrypted = output_file)
    elif task == "-i":
        cipher.ctr_aes_image(iv = BitVector(textstring="counter-mode-ctr"), image_file = input_file, enc_image = output_file)
    elif task == "-r":
        cipher.x931(v0 = BitVector(textstring="counter-mode-ctr"),dt=BitVector(intVal=501,size=128), totalNum = int(input_file), outfile = output_file)
    else:
        sys.exit("Incorrect CLI argument. Please use -e or -d or -i.")    