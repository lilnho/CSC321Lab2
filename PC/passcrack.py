import nltk
import bcrypt
import os
nltk.download('words')

from nltk.corpus import words

def main():

    all_passes = words.words()
    strings = []
    with open('C:/Users/natha/CSC321/CSC321Lab2/PC/shadow_file.txt', 'r') as file:
        for line in file:
            strings.append(line)

    for string in strings:
        first = string.find("$")
        string = string[first:]
        
        b = bytes(string, encoding='utf-8')
        for word in all_passes:
            if len(word) >= 6 and len(word) <= 10:
                # code
                bword = bytes(word, encoding='utf-8')
                if (bcrypt.checkpw(bword, b) == True):
                    print("Password is: %s", word)
        print("Finished checking one string")

if __name__ == "__main__":
    main()