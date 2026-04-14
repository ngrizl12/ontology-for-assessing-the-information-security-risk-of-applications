import os
import re
import json
import math
import bisect
from statistics import mean

import pandas as pd
from owlready2 import *
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
import ssl
import urllib.request

CWE_CHAINS_FILE = os.getenv("CWE_CHAINS_OUTPUT")
cwe_chains_cache = {}

owlready2.reasoning.JAVA_MEMORY = 8000

from pathlib import Path
env_path = Path(__file__).parent.parent.parent / ".local.env"
load_dotenv(env_path)

ONTO_PATH = os.getenv("ONTO_PATH")
CWE_CSV_PATH = os.getenv("CWE_OUTPUT_CSV")
CAPEC_CSV_PATH = os.getenv("CAPEC_OUTPUT")

epss_cache = {}
epss_error_shown = False

cvss_cache = {}

risk_reference_distribution = []

RISK_REFERENCE_FILE = os.getenv("RISK_REFERENCE_OUTPUT")
if RISK_REFERENCE_FILE and os.path.exists(RISK_REFERENCE_FILE):
    with open(RISK_REFERENCE_FILE, 'r', encoding='utf-8') as f:
        risk_reference_distribution = json.load(f)

cve_csv_path = os.getenv("CVE_PROCESSING_OUTPUT")
if cve_csv_path and os.path.exists(cve_csv_path):
    cve_df = pd.read_csv(cve_csv_path)
    for _, row in cve_df.iterrows():
        cve_id = str(row.get('ID', '')).replace('-', '_')
        if pd.notna(row.get('baseScore')):
            cvss_cache[cve_id] = float(row['baseScore'])

def get_epss_score(cve_id):
    global epss_error_shown
    
    if cve_id in epss_cache:
        return epss_cache[cve_id]
    
    cve_api_id = cve_id.replace("_", "-")
    
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        url = f"https://api.first.org/data/v1/epss?cve={cve_api_id}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            if data and 'data' in data and len(data['data']) > 0:
                epss = float(data['data'][0].get('epss', 0))
                epss_cache[cve_id] = epss
                return epss
    
    except Exception as e:
        if not epss_error_shown:
            print(f"  EPSS API недоступен, используем likelihood из CWE/CAPEC")
            epss_error_shown = True
    
    epss_cache[cve_id] = None
    return None

translator = None
try:
    translator = GoogleTranslator(source='en', target='ru')
except:
    pass

translation_cache = {}

def translate_text(text, max_length=500):
    if not text or not translator:
        return text
    if text in translation_cache:
        return translation_cache[text]
    try:
        if len(text) > max_length:
            text_short = text[:max_length] + "..."
            translated = translator.translate(text_short)
        else:
            translated = translator.translate(text)
        translation_cache[text] = translated
        return translated
    except Exception as e:
        translation_cache[text] = text
        return text

if CWE_CSV_PATH and os.path.exists(CWE_CSV_PATH):
    cwe_df = pd.read_csv(CWE_CSV_PATH)
    cwe_dict = {}
    for _, row in cwe_df.iterrows():
        cwe_id = str(row['ID']).strip()
        cwe_dict[cwe_id] = {
            'name': row['Name'] if pd.notna(row['Name']) else cwe_id,
            'likelihood': row['Likelihood_Of_Exploit'] if pd.notna(row['Likelihood_Of_Exploit']) else None,
            'category': row.get('Category', None) if pd.notna(row.get('Category', None)) else None
        }
else:
    cwe_dict = {}

if CWE_CHAINS_FILE and os.path.exists(CWE_CHAINS_FILE):
    with open(CWE_CHAINS_FILE, 'r', encoding='utf-8') as f:
        cwe_chains_cache = json.load(f)
else:
    cwe_chains_cache = {}

if CAPEC_CSV_PATH and os.path.exists(CAPEC_CSV_PATH):
    capec_df = pd.read_csv(CAPEC_CSV_PATH)
    capec_dict = {}
    for _, row in capec_df.iterrows():
        capec_id = str(row['ID']).strip()
        capec_dict[capec_id] = {
            'name': row['Name'] if pd.notna(row['Name']) else capec_id,
            'description': row['Description'] if pd.notna(row['Description']) else "Описание отсутствует",
            'likelihood': row['Likelihood_Of_Attack'] if pd.notna(row['Likelihood_Of_Attack']) else None,
            'typical_severity': row.get('Typical_Severity', None)
        }
else:
    capec_dict = {}
def get_risk_percentile(cvss, epss):
    if not risk_reference_distribution:
        return None
    
    if cvss is None or epss is None or epss <= 0:
        return None
    
    raw_risk = cvss * epss
    rank = bisect.bisect_right(risk_reference_distribution, raw_risk)
    percentile = (rank / len(risk_reference_distribution)) * 100
    
    return percentile

def extract_cwe_id(cwe_obj):
    cwe_str = str(cwe_obj)
    match = re.search(r'CWE[_-]?(\d+)', cwe_str, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe_str

def get_cwe_chain(cwe_id):
    if not cwe_chains_cache:
        return []
    
    return cwe_chains_cache.get(cwe_id, [])

def calculate_chain_risk(cwe_id, base_risk, decay=0.5):
    chain = get_cwe_chain(cwe_id)
    
    if not chain:
        return base_risk
    
    total_risk = base_risk
    
    for i, downstream_cwe in enumerate(chain):
        contribution = base_risk * (decay ** (i + 1))
        total_risk += contribution
    
    return total_risk

def extract_capec_id(capec_obj):
    capec_str = str(capec_obj)
    match = re.search(r'CAPEC[_-]?(\d+)', capec_str, re.IGNORECASE)
    if match:
        return f"CAPEC-{match.group(1)}"
    return capec_str

def get_capec_info(capec_obj):
    capec_id = extract_capec_id(capec_obj)
    if capec_id in capec_dict:
        return {
            'id': capec_id,
            'name': capec_dict[capec_id]['name'],
            'description': capec_dict[capec_id]['description'],
            'likelihood': capec_dict[capec_id]['likelihood']
        }
    else:
        return {
            'id': capec_id,
            'name': capec_id,
            'description': "Описание отсутствует",
            'likelihood': None
        }

def likelihood_weight(value):
    if not value:
        return 1.0
    value = value.lower()
    weights = {
        "very low": 0.5,
        "low": 0.7,
        "medium": 1.0,
        "high": 1.3,
        "very high": 1.6
    }
    return weights.get(value, 1.0)

# Коэффициенты Likelihood коррелируют с EPSS перцентилями
# Основано на анализе risk_reference_distribution (CVSS × EPSS)
LIKELIHOOD_COEFF = {
    'very high': 0.50,    # ~95-й перцентиль EPSS
    'high': 0.20,         # ~75-й перцентиль EPSS
    'medium': 0.05,       # ~50-й перцентиль EPSS (медиана)
    'low': 0.01,          # ~25-й перцентиль EPSS
    'very low': 0.001,    # <10-й перцентиль EPSS
    'not specified': 0.05 
}

SEVERITY_TO_CVSS = {
    'CRITICAL': 9.0,
    'HIGH': 8.0,
    'MEDIUM': 5.5,
    'LOW': 2.5
}

TYPICAL_SEVERITY_COEFF = {
    'very high': 9,
    'high': 7,
    'medium': 5,
    'low': 3
}

onto = get_ontology(f"file://{os.path.abspath(ONTO_PATH)}").load()

def normalize(text):
    if not text:
        return None
    return text.lower().replace("_","").replace("-","").replace(".","")

def parse_cpe(name):
    if not name:
        return None
    
    parts = name.split("_")
    
    if len(parts) < 6:
        return None
    
    if parts[0] != "cpe" or parts[1] != "2" or parts[2] != "3":
        return None
    
    part = parts[3]
    vendor = parts[4]
    product = parts[5]
    
    remaining = parts[6:]
    
    if len(remaining) >= 6:
        version_parts = remaining[:-6]
        update = remaining[-6]
        edition = remaining[-5]
        language = remaining[-4]
        sw_edition = remaining[-3]
        target_sw = remaining[-2]
        target_hw = remaining[-1]
    else:
        version_parts = remaining
        update = edition = language = sw_edition = target_sw = target_hw = "*"
    
    version = None
    if version_parts:
        filtered = [p for p in version_parts if p and p != "*"]
        if filtered:
            version = ".".join(filtered)
    
    return {
        "part": part,
        "vendor": vendor,
        "product": product,
        "version": version,
        "update": update if update and update != "*" else None,
        "edition": edition if edition and edition != "*" else None,
        "language": language if language and language != "*" else None,
        "sw_edition": sw_edition if sw_edition and sw_edition != "*" else None,
        "target_sw": target_sw if target_sw and target_sw != "*" else None,
        "target_hw": target_hw if target_hw and target_hw != "*" else None
    }

def get_cvss(cve, cwes=None):
    props = [
        "hasCVSSScore",
        "cvssScore", 
        "baseScore",
        "impactScore"
    ]
    
    for p in props:
        if hasattr(cve, p):
            val = getattr(cve, p)
            if val:
                try:
                    score = float(val[0])
                    if score > 0:
                        return score
                except:
                    pass
    
    cve_name = str(cve.name) if hasattr(cve, 'name') else str(cve)
    if cve_name in cvss_cache:
        return cvss_cache[cve_name]
    
    if hasattr(cve, "hasSeverity") and cve.hasSeverity:
        severity = str(cve.hasSeverity[0]).upper()
        if severity in SEVERITY_TO_CVSS:
            return SEVERITY_TO_CVSS[severity]
    
    # CWE -> CAPEC -> Typical_Severity
    if cwes is None:
        cwes = getattr(cve, "hasWeakness", [])
    
    for cwe in cwes:
        cwe_id = extract_cwe_id(cwe)
        for capec in getattr(cwe, "exploitedBy", []):
            capec_id = extract_capec_id(capec)
            if capec_id in capec_dict:
                typical_severity = capec_dict[capec_id].get('typical_severity')
                if typical_severity:
                    severity_lower = typical_severity.lower()
                    if severity_lower in TYPICAL_SEVERITY_COEFF:
                        return TYPICAL_SEVERITY_COEFF[severity_lower]
    
    return None

def get_cvss_from_capec(cwes):
    for cwe in cwes:
        cwe_id = extract_cwe_id(cwe)
        # Проверяем CAPEC через exploitedBy в онтологии
        for capec in getattr(cwe, "exploitedBy", []):
            capec_id = extract_capec_id(capec)
            if capec_id in capec_dict:
                typical_severity = capec_dict[capec_id].get('typical_severity')
                if typical_severity:
                    severity_lower = typical_severity.lower()
                    if severity_lower in TYPICAL_SEVERITY_COEFF:
                        return TYPICAL_SEVERITY_COEFF[severity_lower]
    return None

def normalize_version(v):
    if not v or v == "unknown":
        return "unknown"
    
    parts = v.split(".")
    
    numeric_parts = []
    for p in parts:
        num = ""
        for c in p:
            if c.isdigit():
                num += c
            else:
                break
        if num:
            numeric_parts.append(num)
        if len(numeric_parts) >= 3:
            break
    
    if not numeric_parts:
        return "unknown"
    
    return ".".join(numeric_parts[:3])

def show_versions_paginated(versions, version_list, page_size=10):
    page = 0
    total_pages = (len(version_list) + page_size - 1) // page_size
    
    while True:
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, len(version_list))
        
        print(f"\n  Версии {start_idx+1}-{end_idx} из {len(version_list)} (страница {page+1}/{total_pages}):")
        
        for i in range(start_idx, end_idx):
            v = version_list[i]
            count = len(versions[v])
            print(f"    [{i}] {v} ({count} CPE)")
        
        print(f"\n  [n] следующая страница, [p] предыдущая, [0-{len(version_list)-1}] выбрать версию, [q] выход")
        
        choice = input("  Ваш выбор: ").strip().lower()
        
        if choice == 'q':
            return None
        elif choice == 'n':
            if page < total_pages - 1:
                page += 1
            else:
                print("  Это последняя страница")
        elif choice == 'p':
            if page > 0:
                page -= 1
            else:
                print("  Это первая страница")
        elif choice.isdigit() and int(choice) < len(version_list):
            chosen_idx = int(choice)
            chosen_version = version_list[chosen_idx]
            print(f"  Выбрана версия: {chosen_version}")
            return versions[chosen_version]
        else:
            print("  Неверный выбор, попробуйте снова")

def find_cpes(product, version=None, vendor=None, interactive=True):
    matches = []
    
    for cpe in onto.CPE.instances():
        parsed = parse_cpe(cpe.name)
        
        if not parsed:
            continue
        
        p = normalize(parsed["product"])
        v = parsed["version"]
        vend = normalize(parsed.get("vendor", ""))
        
        if p != product:
            continue
        
        if vendor and vend != vendor:
            continue
        
        matches.append((cpe, v, parsed))
    
    if not matches:
        return []
    
    versions = {}
    for cpe, v, parsed in matches:
        key = normalize_version(v)
        if key not in versions:
            versions[key] = []
        versions[key].append(cpe)
    
    def version_sort_key(x):
        if x == "unknown":
            return (1, x)
        try:
            parts = [int(p) for p in x.split(".")]
            return (0, parts)
        except:
            return (1, x)
    
    version_list = sorted(versions.keys(), key=version_sort_key)
    
    if not version:
        if not interactive:
            return [cpe for cpe, v, parsed in matches]
        
        print(f"\n  Найдено {len(matches)} CPE для продукта '{product}'")
        print(f"  Доступно {len(versions)} версий")
        
        version = input("  Введите версию (или нажмите Enter для выбора из списка): ").strip()
        
        if not version:
            print(f"\n  Доступные версии (первые 10 из {len(versions)}):")
            return show_versions_paginated(versions, version_list)
        
        norm_input = normalize_version(version)
        
        if norm_input in versions:
            print(f"  Выбрана версия: {norm_input}")
            return versions[norm_input]
        
        major = version.split(".")[0] if version else ""
        similar = [v for v in version_list if v.startswith(major) and v != "unknown"]
        
        if similar:
            print(f"\n  Версия '{version}' не найдена.")
            print(f"  Найдены версии, начинающиеся с '{major}':")
            
            if len(similar) <= 10:
                for i, v in enumerate(similar):
                    print(f"    [{i}] {v} ({len(versions[v])} CPE)")
                
                choice = input("\n  Выберите версию (номер) или [n] для просмотра всех: ").strip().lower()
                
                if choice == 'n' or choice == 'no':
                    return show_versions_paginated(versions, version_list)
                elif choice.isdigit() and int(choice) < len(similar):
                    chosen_version = similar[int(choice)]
                    print(f"  Выбрана версия: {chosen_version}")
                    return versions[chosen_version]
            else:
                return show_versions_paginated(versions, similar)
        else:
            print(f"\n  Версия '{version}' не найдена.")
            return show_versions_paginated(versions, version_list)
    
    norm_input_version = normalize_version(version)
    
    exact = []
    wildcard = []
    
    for cpe, v, parsed in matches:
        if v is None or v == "*":
            wildcard.append(cpe)
        else:
            norm_cpe_version = normalize_version(v)
            if norm_input_version == norm_cpe_version:
                exact.append(cpe)
            elif version.lower() in v.lower():
                exact.append(cpe)
    
    if exact:
        return exact
    
    if not interactive:
        return wildcard if wildcard else []
    
    print(f"\n  Версия '{version}' не найдена для продукта '{product}'")
    
    major = version.split(".")[0] if version else ""
    similar = [v for v in version_list if v.startswith(major) and v != "unknown"]
    
    if similar:
        print(f"  Найдены версии, начинающиеся с '{major}':")
        if len(similar) <= 10:
            for i, v in enumerate(similar):
                print(f"    [{i}] {v} ({len(versions[v])} CPE)")
            choice = input("\n  Выберите версию (номер) или [n] для просмотра всех: ").strip().lower()
            if choice.isdigit() and int(choice) < len(similar):
                return versions[similar[int(choice)]]
        return show_versions_paginated(versions, similar)
    
    return show_versions_paginated(versions, version_list)

def extract_graph(cpes):
    cves=set()
    cwes=set()
    capecs=set()

    for cpe in cpes:
        for cve in onto.search(type=onto.CVE,affects=cpe):
            cves.add(cve)
            for cwe in getattr(cve,"hasWeakness",[]):
                cwes.add(cwe)
                for capec in getattr(cwe,"exploitedBy",[]):
                    capecs.add(capec)

    return cves,cwes,capecs

ASSET_IMPORTANCE = {
    "1": ("low", 0.25),
    "2": ("medium", 0.5),
    "3": ("high", 0.75),
    "4": ("critical", 1.0)
}

def get_asset_importance(component_name):
    print(f"\n  Оценка важности компонента: {component_name}")
    print("    1 - Low (низкая важность)")
    print("    2 - Medium (средняя важность)")
    print("    3 - High (высокая важность)")
    print("    4 - Critical (критическая важность)")
    
    while True:
        importance = input("  Введите важность (1-4): ").strip()
        if importance in ASSET_IMPORTANCE:
            label, coeff = ASSET_IMPORTANCE[importance]
            print(f"  Важность установлена: {label} (коэффициент {coeff})")
            return label, coeff
        else:
            print("  Неверное значение. Введите число от 1 до 4.")

MAX_RISK_APP = 24.0

def risk_level(score):
    if score >= 18:
        return "Критический"
    if score >= 12:
        return "Высокий"
    if score >= 6:
        return "Средний"
    return "Низкий"

user_input=input("\nВведите компоненты (например 'python 3.9, java 8' или 'google chrome 90.0'): ")

components=[c.strip() for c in user_input.split(",")]

component_risks = []

for comp in components:

    print("\n============================================================")
    print("АНАЛИЗ КОМПОНЕНТА:", comp)
    print("============================================================")

    tokens=comp.split()
    
    if len(tokens) >= 3:
        vendor = normalize(tokens[0])
        product = normalize(tokens[1])
        version = tokens[2] if len(tokens) > 2 else None
    elif len(tokens) == 2:
        if any(c.isdigit() for c in tokens[1]):
            vendor = None
            product = normalize(tokens[0])
            version = tokens[1]
        else:
            vendor = normalize(tokens[0])
            product = normalize(tokens[1])
            version = None
    else:
        vendor = None
        product = normalize(tokens[0]) if tokens else None
        version = None
    
    print(f"  Поиск: vendor={vendor}, product={product}, version={version}")

    cpes=find_cpes(product, version, vendor)

    cves,cwes,capecs=extract_graph(cpes)

    print("\n  Найдено уязвимостей:", len(cves))

    if not cves:
        print("  Уязвимости не найдены")
        component_risks.append({
            "component": comp,
            "max_risk": 0,
            "avg_risk": 0,
            "count": 0,
            "cve_risks": [],
            "importance": "low",
            "importance_coeff": 0.25
        })
        continue

    # Запрашиваем важность компонента
    importance_label, importance_coeff = get_asset_importance(comp)

    print("\n  Уязвимости и риски:")
    cve_risks = []
    for cve in cves:
        cve_cwes = list(getattr(cve, "hasWeakness", []))
        
        cvss = get_cvss(cve, cwes=cve_cwes)
        
        epss = get_epss_score(cve.name)
        
        if epss is None or epss == 0:
            likelihoods = []
            for cwe in cve_cwes:
                cwe_id = extract_cwe_id(cwe)
                if cwe_id in cwe_dict:
                    likelihood = cwe_dict[cwe_id].get('likelihood')
                    if likelihood and likelihood.lower() != 'not specified':
                        if likelihood.lower() in LIKELIHOOD_COEFF:
                            likelihoods.append(LIKELIHOOD_COEFF[likelihood.lower()])
                
                for capec in getattr(cwe, "exploitedBy", []):
                    capec_id = extract_capec_id(capec)
                    if capec_id in capec_dict:
                        likelihood = capec_dict[capec_id].get('likelihood')
                        if likelihood and likelihood.lower() != 'not specified':
                            if likelihood.lower() in LIKELIHOOD_COEFF:
                                likelihoods.append(LIKELIHOOD_COEFF[likelihood.lower()])
            
            epss = max(likelihoods) if likelihoods else None
        
        if cvss is None:
            cvss = get_cvss_from_capec(cve_cwes)
        
        if cvss is not None and epss is not None and epss > 0:
            risk_percentile = get_risk_percentile(cvss, epss)
            
            if risk_percentile is not None:
                normalized_risk = (risk_percentile / 100) * 10
                base_risk = normalized_risk * importance_coeff
            else:
                base_risk = cvss * epss * importance_coeff
        elif cvss is not None and epss is None:
            base_risk = (cvss / 10) * importance_coeff
        elif epss is not None and epss > 0 and cvss is None:
            base_risk = 5 * epss * importance_coeff
        else:
            base_risk = 0
        
        cwe_risks = []
        for cwe in cve_cwes:
            cwe_id = extract_cwe_id(cwe)
            cwe_risks.append(calculate_chain_risk(cwe_id, base_risk))
        
        cve_risk = max(cwe_risks) if cwe_risks else base_risk
        
        cve_risks.append({
            "cve": cve.name,
            "cvss": cvss,
            "epss": epss,
            "risk": cve_risk,
            "importance": importance_label,
            "importance_coeff": importance_coeff
        })
        
        cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
        epss_str = f"{epss:.6f}" if epss is not None else "N/A"
        base_risk_str = f"{base_risk:.6f}" if base_risk > 0 else "N/A"
        
        if cvss is not None and epss is not None and epss > 0:
            risk_percentile = get_risk_percentile(cvss, epss)
            percentile_str = f"percentile={risk_percentile:.1f}%" if risk_percentile else "N/A"
        else:
            percentile_str = "N/A"
        
        chain_multiplier = cve_risk / base_risk if base_risk > 0 else 1.0
        chain_info = f"chain_multiplier={chain_multiplier:.2f}x" if chain_multiplier > 1.0 else "no chain"
        print(f"    {cve.name}: CVSS={cvss_str}, EPSS={epss_str}, {percentile_str}, RISK={cve_risk:.6f} (importance={importance_label}, {chain_info})")
    
    risk_values = [cr["risk"] for cr in cve_risks]
    max_risk = max(risk_values) if risk_values else 0
    avg_risk = mean(risk_values) if risk_values else 0
    count = len(cve_risks)
    
    print(f"\n  Метрики риска компонента:")
    print(f"    Количество уязвимостей: {count}")
    print(f"    Важность компонента: {importance_label} (коэффициент {importance_coeff})")
    print(f"    Максимальный риск (max): {round(max_risk, 6)}")
    print(f"    Средний риск (avg): {round(avg_risk, 6)}")
    
    component_risks.append({
        "component": comp,
        "max_risk": max_risk,
        "avg_risk": avg_risk,
        "count": count,
        "cve_risks": cve_risks,
        "importance": importance_label,
        "importance_coeff": importance_coeff
    })

print("\n" + "="*70)
print("ОБЩИЙ РИСК ПРИЛОЖЕНИЯ")
print("="*70)

if component_risks:
    print("\n  Сводка по компонентам:")
    print("-"*90)
    print(f"  {'Компонент':<25} {'CVE':<5} {'Importance':<12} {'Max Risk':<14} {'Avg Risk':<14}")
    print("-"*90)
    
    for cr in component_risks:
        comp_name = cr["component"][:23] + ".." if len(cr["component"]) > 25 else cr["component"]
        importance = f"{cr['importance']} ({cr['importance_coeff']})"
        print(f"  {comp_name:<25} {cr['count']:<5} {importance:<12} {cr['max_risk']:<14.6f} {cr['avg_risk']:<14.6f}")
    
    total_vulns = sum(cr["count"] for cr in component_risks)
    
    component_max_risks = [cr["max_risk"] for cr in component_risks if cr["count"] > 0]
    
    if component_max_risks:
        max_risk_all = max(component_max_risks)
        
        vuln_factor = math.log(1 + total_vulns)
        app_risk = max_risk_all + vuln_factor
        
        print("-"*90)
        print(f"\n  Расчет риска приложения:")
        print(f"    Max риск среди компонентов: {max_risk_all:.6f}")
        print(f"    Количество уязвимостей (CVE): {total_vulns}")
        print(f"    Логарифмический фактор: log(1 + {total_vulns}) = {vuln_factor:.6f}")
        print(f"\n  ОБЩИЙ РИСК ПРИЛОЖЕНИЯ: {round(app_risk, 2)}/{MAX_RISK_APP}")
        print(f"  УРОВЕНЬ РИСКА: {risk_level(app_risk)}")
    else:
        print("\n  Уязвимые компоненты не найдены")
        print("  ОБЩИЙ РИСК ПРИЛОЖЕНИЯ: 0")
        print("  УРОВЕНЬ РИСКА: Низкий")

print("\n" + "="*70)
print("АНАЛИЗ ЗАВЕРШЕН")
print("="*70)