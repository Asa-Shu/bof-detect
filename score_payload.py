threshold = 100  # 攻撃か判断する閾値
length_score_factor = 20  # ペイロードの長さによるスコア加算の度合いを調整する係数
frequency_score_factor = 20
# 疑わしいオペコード（アーキテクチャ別）
suspicious_opcodes = {
    "x86": {
        "\\x90": 1,  # NOP
        "\\x58": 2,  # POP EAX
        "\\x5a": 2,  # POP EDX
        "\\x89": 2,  # MOV, variant
        "\\x8b": 2,  # MOV, variant
        "\\xb8": 2,  # MOV EAX, imm32
        "\\x05": 2,  # ADD EAX, imm32
        "\\x50": 2,  # PUSH EAX
        "\\x68": 2,  # PUSH imm32
        "\\xc3": 2,  # RET
        "\\xcc": 2,  # INT3
        "\\xcd": 2,  # INT imm8
        "\\xe8": 2,  # CALL
        "\\xe9": 2,  # JMP
        "\\xeb": 2,  # JMP short
        "\\x74": 2,  # JZ
        "\\x75": 2,  # JNZ
        "\\x80": 2,  # ADD, variant
        "\\x81": 2,  # ADD, variant
        "\\x83": 2,  # ADD, variant
        "\\xc6": 2,  # MOV, variant
        "\\xc7": 2,  # MOV, variant
        "\\xfe": 2,  # INC, variant
        "\\xff": 2,  # INC, variant
    },
    "ARM": {
        "\\x00\\x00\\xa0\\xe1": 2,  # MOV
        "\\x01\\x30\\x8f\\xe2": 2,  # ADD
        "\\x01\\x20\\x42\\xe0": 2,  # SUB
        "\\x70\\x40\\x2d\\xe9": 2,  # PUSH
    },
}


# ペイロードとアーキテクチャを引数に受け取る
def score_payload(payload, architecture):
    score = 0  # 怪しさを表すスコア
    prev_byte = None  # 前のバイト
    consecutive_count = 0  # 同一バイトが連続した回数
    byte_counts = dict()  # バイトの出現回数

    # * 入力が長いほど加点
    score += len(payload) / length_score_factor

    for i in range(0, len(payload), 4):
        byte = payload[i : i + 4]  # バイトごとのまとまりに区切る
        byte_counts[byte] = byte_counts.get(byte, 0) + 1  # バイトの出現回数を加算

        # * 同一バイトが連続するほど加点
        if byte == prev_byte:
            consecutive_count += 1
            # 2回以上連続した場合のみ加点する
            if consecutive_count >= 2:
                score += consecutive_count
        else:
            consecutive_count = 0

        # * 命令のようなバイト列があれば加点
        if byte in suspicious_opcodes.get(architecture, {}):  # キーが存在しない場合{}を返す
            score += suspicious_opcodes[architecture][byte]

        # * ASCIIで0x20〜0x7Eの範囲にないものがあれば加点
        x = int(byte[2:], 16)
        if not 0x20 <= x <= 0x7E:
            score += 1

        prev_byte = byte

    # * 頻繁に出てくるバイトがあれば加点
    for byte, count in byte_counts.items():
        if count >= 2:
            score += count / frequency_score_factor

    return score


def main():
    payload = input("payload: ")
    architecture = input("architecture: ")
    if architecture == "":
        architecture = "x86"

    result = score_payload(payload, architecture)

    print(f"Payload score: {result}")
    if result > threshold:
        print("The payload may be malicious.")
    else:
        print("The payload seems to be safe.")


if __name__ == "__main__":
    main()
