import subprocess,re
out=subprocess.check_output("iptables -t nat -L --line-numbers", shell=True)
# print(out.decode("utf-8"))
for val in out.decode("utf-8").split("\n"):
    if re.search("8888",val):
        print(val[0])