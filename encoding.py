def encode_text(text):
    encoded_text = text.encode("ascii")
    hex_text = encoded_text.hex()
    return "".join(["\\x" + hex_text[i : i + 2] for i in range(0, len(hex_text), 2)])


with open("input.txt", "r") as input_file, open("output.txt", "w") as output_file:
    for line in input_file:
        line = line.rstrip("\n")
        encoded_line = encode_text(line)
        output_file.write(encoded_line + "\n")
