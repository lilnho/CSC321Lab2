import nltk
import bcrypt
nltk.download('words')

from datetime import datetime
from nltk.corpus import words

def main():

    all_passes = words.words()
    strings = []
    with open('C:/Users/natha/CSC321/CSC321Lab2/PC/shadow_file.txt', 'r') as file:
        for line in file:
            parts = line.strip().split(":")
            strings.append([parts[0], parts[1]])

    #filter possible passwords to >= 6 and <= 10 to save time
    possible_passes = [word for word in all_passes if 6 <= len(word) <= 10]
    
    start = datetime.now()
    formatted = start.strftime('%m-%d %H:%M:%S')
    print("Started checking at:",formatted)
    
    '''
    # Ori -> airway 
    for pair in strings:
        b = bytes(pair[1], encoding='utf-8')
        airway = bytes("airway", encoding='utf-8')
        if (bcrypt.checkpw(airway, b) == True):
            print(pair[0])
    '''
    
    for word in possible_passes:
        for pair in strings:
            b = bytes(pair[1], encoding='utf-8')
            # code
            bword = bytes(word, encoding='utf-8')
            if (bcrypt.checkpw(bword, b) == True):
                print("User is:", pair[0])
                print("Password is:", word)
                timeFound = datetime.now()
                formatted = timeFound.strftime('%m-%d %H:%M:%S')
                print("Started checking at:",formatted)
    print("Finished checking one string")

if __name__ == "__main__":
    main()