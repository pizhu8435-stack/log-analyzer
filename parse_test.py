from parser import parse_log

with open("access.log", "r") as f:

    for line in f:

        result = parse_log(line)

        print(result)