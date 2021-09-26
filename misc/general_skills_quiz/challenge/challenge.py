#!/usr/bin/python3.8

import random, base64, codecs, string, urllib.parse,re

art = r"""
##############################'               `##############################  
############################'                   `############################
###'`#############'`######!                       !######'`#############'`###
####  ###########  #######                         #######  ###########  ####
####. `#' \' \#`  #######!           DUCTF         !#######  '#/ `/ `#' .####
#####. !\  i  i .########                           ########. i  i  /! .#####
######   `--`--.#########                           #########.--'--'   ######
######L        `#####^^##                           ##^^#####'        J######
#######.   .'   ""~   ###    #.                 .#  ###   ~""   `.   .#######
########.  ;      .e#####!    ##.             .##  !#####e,      ;  .########
#########   `.############     ###.         .###   ############.'   #########
########    .#############!     ##`########'##    !#############.    ########
#JT&yd#     ################.    #    ##    #   .################     #by&TL#
                                 #    ##    #
                                 #.   ##   .#
                                 `#        #'
                                  `########'
"""

flag = r"""
   .^.
  (( ))
   |#|_______________________________
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||########DOWNUNDERCTF##########|
   |#||########(DUCTF 2021)##########|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#||##############################|
   |#|'------------------------------'
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|
   |#|  DUCTF{you_aced_the_quiz!_have_a_gold_star_champion}
   |#|
   |#|
   |#|   
  //|\\
"""

# Wordlist is from https://www.mit.edu/~ecprice/wordlist.10000
word_file = "./wordlist.txt"
words = open(word_file).read().splitlines()

# function to generate a random word n amount of times 
def generate_random_word(n):
    tmp = ""
    for _ in range(n):
        tmp += (random.choice(words)) + "_"
    return tmp.strip("_")

# Develops a question where n is the amount of words and q is the question string
def question(p, q):
    plaintext = p
    print(q)
    # Uncomment below line if you need answer
    # print(plaintext)
    user_answer = input()
    if (user_answer == plaintext):
        return True
    else:
        return False

# Logic of the right or wrong answer. Pass in the question function and a compliment to the user if they get it right.
def logic(full_q, compliment): 
    if (full_q):
        print(compliment)
        print()
    else:
        print()
        print("\t\t\t\tYOU CARKED IT!")
        print()
        print(art)
        exit()

# Question 1 - Basic Maths
q1_plaintext = "2"
q1_math = "Answer this maths question: 1+1=?" 

# Question 2 - Hex -> Base 10
q2_plaintext = str(random.randint(10,255))
q2_hex2base10 ="Decode this hex string and provide me the original number (base 10): " + hex(int(q2_plaintext))

# Question 3 - Hex -> ASCII
q3_plaintext = str(random.choice(string.ascii_letters))
q3_hex2ascii = "Decode this hex string and provide me the original ASCII letter: " + q3_plaintext.encode("utf-8").hex()

# Question 4 - URL Encoded -> ASCII Symbols
q4_plaintext = random.choice(string.punctuation) + random.choice(string.punctuation) + random.choice(string.punctuation)
q4_urlencode2ascii = "Decode this URL encoded string and provide me the original ASCII symbols: " + urllib.parse.quote(q4_plaintext)

# Question 5 - Base64 -> ASCII
q5_plaintext = generate_random_word(4)
q5_b64decode = "Decode this base64 string and provide me the plaintext: " + base64.b64encode(str.encode(q5_plaintext)).decode("UTF-8")

# Question 6 - ASCII -> Base64
q6_start = generate_random_word(4)
q6_end = base64.b64encode(str.encode(q6_start)).decode("UTF-8")
q6_b64encode = "Encode this plaintext string and provide me the Base64: " + q6_start

# Question 7 - ROT13 -> ASCII
q7_plaintext = generate_random_word(4)
q7_r13decode = "Decode this rot13 string and provide me the plaintext: " + codecs.encode((q7_plaintext),'rot13')

# Question 8 - ASCII -> ROT13
q8_start = generate_random_word(4)
q8_end = codecs.encode(q8_start,'rot13')
q8_r13encode = "Encode this plaintext string and provide me the ROT13 equilavent: " + q8_start

# Question 9 - Binary -> Base 10
q9_plaintext = str(random.randint(1000,9999))
q9_binarydecode = "Decode this binary string and provide me the original number (base 10): " + bin(int(q9_plaintext))

# Question 10 - Base10 -> Binary
q10_start = str(random.randint(1000,9999))
q10_mid = bin(int(q10_start))
q10_binaryencode = "Encode this number and provide me the binary equivalent: " + q10_start

# Question 11 - CTF Q
q11_plaintext = "DUCTF"
q11_problem = "Final Question, what is the best CTF competition in the universe?"

# Main
print("Welcome to the DUCTF Classroom! Cyber School is now in session!")
input("Press enter when you are ready to start your 30 seconds timer for the quiz...")
print("Woops the time is always ticking...")
logic(question(q1_plaintext, q1_math), "Well I see you are not a bludger then.")
logic(question(q2_plaintext, q2_hex2base10), "You're better than a dog's breakfast at least.")
logic(question(q3_plaintext, q3_hex2ascii), "Come on this isn't hard yakka")
logic(question(q4_plaintext, q4_urlencode2ascii), "You haven't gone walkabout yet. Keep going!")
logic(question(q5_plaintext, q5_b64decode), "That's a fair crack of the whip.")
logic(question(q6_end, q6_b64encode), "Fair dinkum! That's not bad.")
logic(question(q7_plaintext, q7_r13decode), "Don't spit the dummy yet!")
logic(question(q8_end, q8_r13encode), "You're sussing this out pretty quickly.")
logic(question(q9_plaintext, q9_binarydecode), "Crikey, can you speak computer?")
logic(question(q10_mid, q10_binaryencode), "You're better than a bunnings sausage sizzle.")
logic(question(q11_plaintext, q11_problem), "Bloody Ripper! Here is the grand prize!")
print()
print(flag)








