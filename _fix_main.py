bad  = r'    return [{\"date\": d, \"scans\": buckets[d], \"label\": d[5:]} for d in days_list]'
good = '    return [{"date": d, "scans": buckets[d], "label": d[5:]} for d in days_list]'

with open("main.py", "r", encoding="utf-8") as f:
    text = f.read()

if bad in text:
    text = text.replace(bad, good)
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("Fixed.")
else:
    print("Pattern not found — showing line 356:")
    for i, line in enumerate(text.splitlines(), 1):
        if 350 <= i <= 360:
            print(f"{i}: {repr(line)}")
