from detector import detect_attack
with open("access.log","r") as f:
    for line in f:
        result = detect_attack(line)
        if result:
            print(f"[!]检测到攻击:{result}")
            print(line)