from owlready2 import *
import os
import re
from dotenv import load_dotenv

load_dotenv(".local.env")

ONTO_PATH = os.getenv("ONTO_PATH")

def normalize(text):
    if not text or text in ["*", "-", "na", ""]:
        return None
    return str(text).lower().replace(":", "").replace(".", "").replace("-", "").replace("_", "").strip()

def parse_cpe(cpe_name):
    if not cpe_name or not isinstance(cpe_name, str) or not cpe_name.startswith("cpe_2_3_"):
        return None
    
    parts = cpe_name.split("_")
    
    if len(parts) < 14:
        return None
        
    return {
        "part": parts[3],
        "vendor": parts[4],
        "product": parts[5],
        "version": parts[6] if parts[6] not in ["", "*"] else None,
        "update": parts[7] if parts[7] not in ["", "*"] else None,
        "edition": parts[8] if parts[8] not in ["", "*"] else None,
        "language": parts[9] if parts[9] not in ["", "*"] else None,
        "sw_edition": parts[10] if len(parts) > 10 and parts[10] not in ["", "*"] else None,
        "target_sw": parts[11] if len(parts) > 11 and parts[11] not in ["", "*"] else None,
        "target_hw": parts[12] if len(parts) > 12 and parts[12] not in ["", "*"] else None,
        "other": parts[13] if len(parts) > 13 and parts[13] not in ["", "*"] else None
    }

def extract_version(parsed):
    version_parts = []
    
    if parsed.get("version") and parsed["version"] not in ["*", "-", ""]:
        version_parts.append(parsed["version"])
    
    if parsed.get("update") and parsed["update"] not in ["*", "-", ""]:
        version_parts.append(parsed["update"])
    
    if parsed.get("edition") and parsed["edition"] not in ["*", "-", ""]:
        if re.search(r'^\d+$', parsed["edition"]) or re.search(r'\.', parsed["edition"]):
            version_parts.append(parsed["edition"])
    
    if parsed.get("sw_edition") and parsed["sw_edition"] not in ["*", "-", ""]:
        if re.search(r'\d', parsed["sw_edition"]):
            version_parts.append(parsed["sw_edition"])
    
    if version_parts:
        full_version = ".".join(version_parts)
        if re.search(r'\d', full_version):
            return full_version
    
    return None

onto = get_ontology(f"file://{os.path.abspath(ONTO_PATH)}").load()

print("CVE count:", len(list(onto.CVE.instances())))
print("CPE count:", len(list(onto.CPE.instances())))

user_input = input("\nВведите продукт (например 'python' или 'python 3.9'): ")

tokens = user_input.strip().split()
product_input = normalize(tokens[0])
version_input = tokens[1] if len(tokens) > 1 else None

all_cpe = list(onto.CPE.instances())
product_matches = []
target_sw_matches = []

for cpe in all_cpe:
    parsed = parse_cpe(cpe.name)
    if not parsed:
        continue

    product = normalize(parsed.get("product"))
    version = extract_version(parsed)
    target_sw = normalize(parsed.get("target_sw"))
    
    if product and product == product_input:
        product_matches.append({"cpe": cpe, "parsed": parsed, "version": version})

    if target_sw and target_sw == product_input:
        target_sw_matches.append({"cpe": cpe, "parsed": parsed, "version": version})

selected_cpes = []

if version_input:
    exact_matches = [match["cpe"] for match in product_matches if match["version"] and version_input in match["version"]]
    
    if exact_matches:
        print(f"\nНайдено точное совпадение: {len(exact_matches)} CPE")
        selected_cpes = exact_matches
    else:
        print(f"\nНе найдено CPE с product='{product_input}' и version='{version_input}'")
        
        all_versions = sorted(set(m["version"] for m in product_matches if m["version"] is not None))
        
        if all_versions:
            print("\nДоступные версии:")
            for i, ver in enumerate(all_versions[:20]):
                count = len([m for m in product_matches if m["version"] == ver])
                print(f"  {i}: {ver} ({count} CPE)")
        exit()

elif product_matches:
    versions_dict = {}
    for match in product_matches:
        ver = match["version"]
        if ver not in versions_dict:
            versions_dict[ver] = []
        versions_dict[ver].append(match["cpe"])
    
    versions = sorted([v for v in versions_dict.keys() if v is not None])
    
    if len(versions) == 1:
        selected_cpes = versions_dict[versions[0]]
        print(f"\nНайдена единственная версия: {versions[0]}")
    
    elif versions:
        print("\nДоступные версии:")
        for i, ver in enumerate(versions[:20]):
            count = len(versions_dict[ver])
            print(f"  {i}: {ver}")
        
        choice = int(input("\nВыберите номер версии: "))
        chosen_version = versions[choice]
        selected_cpes = versions_dict[chosen_version]
        print(f"\nВыбрана версия: {chosen_version}")
    else:
        print("Не найдено версий с цифрами")
        exit()

elif target_sw_matches:
    print(f"\nНайдено совпадение по target_sw: {len(target_sw_matches)} CPE")
    selected_cpes = [m["cpe"] for m in target_sw_matches]

else:
    print("CPE не найдено")
    exit()

print(f"\nАнализ для {len(selected_cpes)} CPE...")

all_cves = []
for cpe in selected_cpes:
    cves = list(onto.search(type=onto.CVE, affects=cpe))
    all_cves.extend(cves)

if not all_cves:
    print("Уязвимости не найдены")
    exit()

unique_cves = list(set(all_cves))
print(f"\nНайдено уязвимостей: {len(unique_cves)}")

for cve in unique_cves[:20]:
    print(f"CVE: {cve.name}")
    if hasattr(cve, "hasWeakness"):
        for cwe in cve.hasWeakness:
            print(f"  CWE: {cwe.name}")
    print()