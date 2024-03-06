import nltk
nltk.download('words')

from nltk.corpus import words

def main():

    all_passes = words.words()
    strings = []
    with open('shadow_file.txt', 'r') as file:
        for line in file:
            strings.append(line)

    for string in strings:
        for word in all_passes:
            if len(word) >= 6 and len(word) <= 10:
                # code


if __name__ == "__main__":
    main()