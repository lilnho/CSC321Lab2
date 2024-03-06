

def main():
    strings = []
    with open('shadow_file.txt', 'r') as file:
        for line in file:
            strings.append(line)

    for string in strings:
        # code


if __name__ == "__main__":
    main()