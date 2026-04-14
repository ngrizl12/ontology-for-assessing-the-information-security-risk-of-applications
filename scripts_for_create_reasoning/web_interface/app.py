import streamlit as st
import pandas as pd
import json
import os
import re
import math
import bisect
import requests
from pathlib import Path
from statistics import mean
from owlready2 import *
import ssl
import urllib.request

YADISK_FILES = {
    "security_ontology_full.owl": "https://disk.360.yandex.ru/d/-_sQlbE_G-Hvog",
    "cwe_all.csv": "https://disk.360.yandex.ru/d/JG_e81Q-lqthQA",
    "capec_all.csv": "https://disk.360.yandex.ru/d/LWInP1emg_xCHA",
    "cve_all_done.csv": "https://disk.360.yandex.ru/d/kF-DPhyPmWC7_A",
    "cwe_chains.json": "https://disk.360.yandex.ru/d/kpstkUDrpEo_qA",
    "risk_reference_distribution.json": "https://disk.360.yandex.ru/d/Tu7XjDS5STVP6w",
}

def download_from_yadisk(public_url, output_path):
    if os.path.exists(output_path):
        if os.path.getsize(output_path) < 1000:
            os.remove(output_path)
        else:
            return True
    try:
        api_url = "https://cloud-api.yandex.net/v1/disk/public/resources/download"
        response = requests.get(api_url, params={"public_key": public_url}, timeout=30)
        response.raise_for_status()
        download_url = response.json()["href"]
        r = requests.get(download_url, stream=True, timeout=120)
        r.raise_for_status()
        with open(output_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        st.error(f"Ошибка загрузки {output_path}: {e}")
        return False

ONTO_PATH = "security_ontology_full.owl"
CWE_CSV_PATH = "cwe_all.csv"
CAPEC_CSV_PATH = "capec_all.csv"
CVE_PROCESSING_OUTPUT = "cve_all_done.csv"
CWE_CHAINS_FILE = "cwe_chains.json"
RISK_REFERENCE_FILE = "risk_reference_distribution.json"

st.set_page_config(
    page_title="Система оценки рисков безопасности",
    layout="wide",
    initial_sidebar_state="expanded"
)

css_file = Path(__file__).parent / "styles.css"
if css_file.exists():
    with open(css_file, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

if 'step' not in st.session_state: st.session_state.step = 0
if 'components' not in st.session_state: st.session_state.components = []
if 'component_versions' not in st.session_state: st.session_state.component_versions = {}
if 'component_importance' not in st.session_state: st.session_state.component_importance = {}
if 'analysis_results' not in st.session_state: st.session_state.analysis_results = []
if 'data_loaded' not in st.session_state: st.session_state.data_loaded = False
if 'selected_component' not in st.session_state: st.session_state.selected_component = None

if not st.session_state.data_loaded:
    loading_placeholder = st.empty()
    progress_placeholder = st.empty()

    def update_loading(step_text, progress_value):
        with loading_placeholder.container():
            st.markdown(f"""
            <div class="loading-container">
                <div class="shield-icon">🛡️</div>
                <div class="spinner"></div>
                <div class="loading-text">Загрузка системы оценки рисков...</div>
                <div class="loading-step">{step_text}</div>
            </div>
            """, unsafe_allow_html=True)
        with progress_placeholder:
            st.progress(progress_value)

    update_loading("Загрузка файлов данных...", 5)
    for filename, url in YADISK_FILES.items():
        update_loading(f"Загрузка {filename}...", 5)
        download_from_yadisk(url, filename)

    update_loading("Загрузка онтологии безопасности...", 20)
    onto = None
    cpe_list = []
    if os.path.exists(ONTO_PATH):
        onto = get_ontology(f"file://{os.path.abspath(ONTO_PATH)}").load()
        try:
            cpe_list = list(onto.CPE.instances())
        except Exception:
            cpe_list = []

    update_loading("Обработка онтологии...", 35)
    epss_cache, cvss_cache, cwe_chains_cache = {}, {}, {}
    risk_reference_distribution = []

    if os.path.exists(RISK_REFERENCE_FILE):
        with open(RISK_REFERENCE_FILE, 'r', encoding="utf-8") as f:
            risk_reference_distribution = json.load(f)

    update_loading("Загрузка данных CVE...", 50)
    if os.path.exists(CVE_PROCESSING_OUTPUT):
        cve_df = pd.read_csv(CVE_PROCESSING_OUTPUT)
        for _, row in cve_df.iterrows():
            cve_id = str(row.get('ID', '')).replace('-', '_')
            if pd.notna(row.get('baseScore')):
                cvss_cache[cve_id] = float(row['baseScore'])

    update_loading("Загрузка цепочек CWE...", 65)
    if os.path.exists(CWE_CHAINS_FILE):
        with open(CWE_CHAINS_FILE, 'r', encoding="utf-8") as f:
            cwe_chains_cache = json.load(f)

    update_loading("Обработка данных CWE...", 75)
    cwe_dict = {}
    if os.path.exists(CWE_CSV_PATH):
        cwe_df = pd.read_csv(CWE_CSV_PATH)
        for _, row in cwe_df.iterrows():
            cwe_id = str(row['ID']).strip()
            cwe_dict[cwe_id] = {
                'name': row['Name'] if pd.notna(row['Name']) else cwe_id,
                'likelihood': row['Likelihood_Of_Exploit'] if pd.notna(row['Likelihood_Of_Exploit']) else None,
                'category': row.get('Category', None) if pd.notna(row.get('Category', None)) else None
            }

    update_loading("Обработка данных CAPEC...", 85)
    capec_dict = {}
    if os.path.exists(CAPEC_CSV_PATH):
        capec_df = pd.read_csv(CAPEC_CSV_PATH)
        for _, row in capec_df.iterrows():
            capec_id = str(row['ID']).strip()
            capec_dict[capec_id] = {
                'name': row['Name'] if pd.notna(row['Name']) else capec_id,
                'description': row['Description'] if pd.notna(row['Description']) else "Описание отсутствует",
                'likelihood': row['Likelihood_Of_Attack'] if pd.notna(row['Likelihood_Of_Attack']) else None,
                'typical_severity': row.get('Typical_Severity', None)
            }

    update_loading("Финализация...", 95)
    import time
    time.sleep(0.3)
    update_loading("Система готова к работе!", 100)
    time.sleep(0.2)

    loading_placeholder.empty()
    progress_placeholder.empty()

    st.session_state.data_loaded = True
    st.session_state.onto = onto
    st.session_state.CPE_LIST = cpe_list
    st.session_state.epss_cache = epss_cache
    st.session_state.cvss_cache = cvss_cache
    st.session_state.cwe_chains_cache = cwe_chains_cache
    st.session_state.risk_reference_distribution = risk_reference_distribution
    st.session_state.cwe_dict = cwe_dict
    st.session_state.capec_dict = capec_dict

else:
    onto = st.session_state.onto
    CPE_LIST = st.session_state.CPE_LIST
    epss_cache = st.session_state.epss_cache
    cvss_cache = st.session_state.cvss_cache
    cwe_chains_cache = st.session_state.cwe_chains_cache
    risk_reference_distribution = st.session_state.risk_reference_distribution
    cwe_dict = st.session_state.cwe_dict
    capec_dict = st.session_state.capec_dict

SEVERITY_TO_CVSS = {'CRITICAL': 9.0, 'HIGH': 8.0, 'MEDIUM': 5.5, 'LOW': 2.5}
TYPICAL_SEVERITY_COEFF = {'very high': 9, 'high': 7, 'medium': 5, 'low': 3}
ASSET_IMPORTANCE = {
    "1": ("low", 0.25),
    "2": ("medium", 0.5),
    "3": ("high", 0.75),
    "4": ("critical", 1.0)
}
MAX_RISK_APP = 24.0

def normalize(text):
    if not text: return None
    return text.lower().replace("_","").replace("-","").replace(".","")

def normalize_version(v):
    if not v or v == "unknown": return "unknown"
    parts = v.split(".")
    numeric_parts = []
    for p in parts:
        num = ""
        for c in p:
            if c.isdigit(): num += c
            else: break
        if num: numeric_parts.append(num)
        if len(numeric_parts) >= 3: break
    return ".".join(numeric_parts[:3]) if numeric_parts else "unknown"

def parse_cpe(name):
    if not name: return None
    parts = name.split("_")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2" or parts[2] != "3":
        return None
    part, vendor, product = parts[3], parts[4], parts[5]
    remaining = parts[6:]
    if len(remaining) >= 6:
        version_parts = remaining[:-6]
        update, edition, language = remaining[-6], remaining[-5], remaining[-4]
        sw_edition, target_sw, target_hw = remaining[-3], remaining[-2], remaining[-1]
    else:
        version_parts = remaining
        update = edition = language = sw_edition = target_sw = target_hw = "*"
    version = ".".join([p for p in version_parts if p and p != "*"]) if version_parts else None
    return {
        "part": part, "vendor": vendor, "product": product, "version": version,
        "update": update if update and update != "*" else None,
        "edition": edition if edition and edition != "*" else None,
        "language": language if language and language != "*" else None,
        "sw_edition": sw_edition if sw_edition and sw_edition != "*" else None,
        "target_sw": target_sw if target_sw and target_sw != "*" else None,
        "target_hw": target_hw if target_hw and target_hw != "*" else None
    }

def extract_cwe_id(cwe_obj):
    match = re.search(r'CWE[_-]?(\d+)', str(cwe_obj), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else str(cwe_obj)

def extract_capec_id(capec_obj):
    match = re.search(r'CAPEC[_-]?(\d+)', str(capec_obj), re.IGNORECASE)
    return f"CAPEC-{match.group(1)}" if match else str(capec_obj)

def get_cwe_chain(cwe_id):
    return cwe_chains_cache.get(cwe_id, []) if cwe_chains_cache else []

def calculate_chain_risk(cwe_id, base_risk, decay=0.5):
    chain = get_cwe_chain(cwe_id)
    if not chain: return base_risk
    return base_risk + sum(base_risk * (decay ** (i + 1)) for i in range(len(chain)))

def risk_level(score):
    if score >= 18: return "Критический"
    if score >= 12: return "Высокий"
    if score >= 6: return "Средний"
    return "Низкий"

def get_epss_score(cve_id):
    if cve_id in epss_cache: return epss_cache[cve_id]
    cve_api_id = cve_id.replace("_", "-")
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        url = f"https://api.first.org/data/v1/epss?cve={cve_api_id}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
            data = json.loads(response.read().decode())
            if data and 'data' in data and len(data['data']) > 0:
                epss = float(data['data'][0].get('epss', 0))
                epss_cache[cve_id] = epss
                return epss
    except Exception:
        pass
    epss_cache[cve_id] = None
    return None

def get_cvss(cve, cwes=None):
    for p in ["hasCVSSScore", "cvssScore", "baseScore", "impactScore"]:
        if hasattr(cve, p):
            val = getattr(cve, p)
            if val:
                try:
                    score = float(val[0])
                    if score > 0: return score
                except:
                    pass
    cve_name = str(cve.name) if hasattr(cve, 'name') else str(cve)
    if cve_name in cvss_cache: return cvss_cache[cve_name]
    if hasattr(cve, "hasSeverity") and cve.hasSeverity:
        severity = str(cve.hasSeverity[0]).upper()
        if severity in SEVERITY_TO_CVSS: return SEVERITY_TO_CVSS[severity]
    if cwes is None: cwes = getattr(cve, "hasWeakness", [])
    for cwe in cwes:
        for capec in getattr(cwe, "exploitedBy", []):
            capec_id = extract_capec_id(capec)
            if capec_id in capec_dict:
                ts = capec_dict[capec_id].get('typical_severity')
                if ts and isinstance(ts, str) and ts.lower() in TYPICAL_SEVERITY_COEFF:
                    return TYPICAL_SEVERITY_COEFF[ts.lower()]
    return None

def get_risk_percentile(cvss, epss):
    if not risk_reference_distribution or cvss is None or epss is None or epss <= 0:
        return None
    raw_risk = cvss * epss
    rank = bisect.bisect_right(risk_reference_distribution, raw_risk)
    return (rank / len(risk_reference_distribution)) * 100

def find_cpes_for_product(product, version=None, vendor=None):
    if not onto or not CPE_LIST:
        return [], {}
    matches = []
    product_norm = normalize(product)
    for cpe in CPE_LIST:
        parsed = parse_cpe(cpe.name)
        if not parsed: continue
        if normalize(parsed["product"]) != product_norm: continue
        if vendor and normalize(parsed.get("vendor", "")) != normalize(vendor): continue
        matches.append((cpe, parsed["version"], parsed))
    if not matches: return [], {}
    versions = {}
    for cpe, v, parsed in matches:
        key = normalize_version(v)
        if key not in versions: versions[key] = []
        versions[key].append(cpe)
    return matches, versions

def get_version_list(versions_dict):
    def sort_key(x):
        if x == "unknown": return (1, x)
        try: return (0, [int(p) for p in x.split(".")])
        except: return (1, x)
    return sorted(versions_dict.keys(), key=sort_key)

def extract_graph(cpes):
    if not onto: return set(), set(), set()
    cves, cwes, capecs = set(), set(), set()
    for cpe in cpes:
        for cve in onto.search(type=onto.CVE, affects=cpe):
            cves.add(cve)
            for cwe in getattr(cve, "hasWeakness", []):
                cwes.add(cwe)
                for capec in getattr(cwe, "exploitedBy", []):
                    capecs.add(capec)
    return cves, cwes, capecs

st.title("Система оценки рисков безопасности веб-приложений")
st.markdown("**Автоматизированная оценка рисков на основе онтологической модели**")

if not onto:
    st.error("Онтология не загружена!")
    st.stop()

with st.sidebar:
    st.header("Настройки")
    st.subheader("Шкала рисков")
    st.markdown('<div class="risk-level risk-low-level">Низкий (0–5)</div>', unsafe_allow_html=True)
    st.markdown('<div class="risk-level risk-medium-level">Средний (6–11)</div>', unsafe_allow_html=True)
    st.markdown('<div class="risk-level risk-high-level">Высокий (12–17)</div>', unsafe_allow_html=True)
    st.markdown('<div class="risk-level risk-critical-level">Критический (18–24)</div>', unsafe_allow_html=True)

    st.divider()
    st.subheader("Важность компонента")
    st.markdown("""
    <div class="importance-info">
    <b>Коэффициенты важности:</b><br>
    • <b>1 — Low</b> (0.25): Не критичный компонент<br>
    • <b>2 — Medium</b> (0.50): Обычный компонент<br>
    • <b>3 — High</b> (0.75): Важный компонент<br>
    • <b>4 — Critical</b> (1.0): Критическая инфраструктура
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.subheader("Источники данных")
    st.markdown("""
    <div class="sources-info">
    <b>Источники данных:</b><br>
    • <b>NVD</b> — CVE (уязвимости)<br>
    • <b>MITRE CWE</b> — слабости<br>
    • <b>MITRE CAPEC</b> — атаки<br>
    • <b>FIRST EPSS</b> — эксплуатация
    </div>
    """, unsafe_allow_html=True)

if st.session_state.step == 0:
    st.header("Шаг 1: Введите компоненты")

    with st.form(key="step1_form"):
        components_input = st.text_area(
            "Компоненты (через запятую)",
            placeholder="python 3.9, java 8, google chrome 90.0",
            height=100
        )

        col1, col2 = st.columns([3, 1])
        with col1:
            submit_btn = st.form_submit_button(
                "Далее: Выбор версий", type="primary", use_container_width=True
            )
            if submit_btn:
                if not components_input:
                    st.error("Введите хотя бы один компонент!")
                else:
                    st.session_state.components = [
                        c.strip() for c in components_input.split(",")
                    ]
                    st.session_state.step = 1
                    st.rerun()
        with col2:
            st.write("")

    st.stop()

if st.session_state.step == 1:
    st.header("Шаг 2: Выберите версии и важность")

    versions_found = {}
    component_importance = {}

    for idx, comp in enumerate(st.session_state.components):
        st.markdown(f"### {idx + 1}. {comp}")
        tokens = comp.split()

        if len(tokens) >= 3:
            vendor, product, version = normalize(tokens[0]), normalize(tokens[1]), tokens[2]
        elif len(tokens) == 2:
            if any(c.isdigit() for c in tokens[1]):
                vendor, product, version = None, normalize(tokens[0]), tokens[1]
            else:
                vendor, product, version = normalize(tokens[0]), normalize(tokens[1]), None
        else:
            vendor, product, version = None, normalize(tokens[0]) if tokens else None, None

        matches, versions_dict = find_cpes_for_product(product, version, vendor)
        version_list = get_version_list(versions_dict) if versions_dict else []

        select_key = f"ver_select_{idx}"
        input_key = f"ver_input_{idx}"
        imp_key = f"imp_select_{idx}"

        version_selected = False

        if version:
            st.success(f"Версия указана: **{version}**")
            if version in versions_dict:
                versions_found[comp] = {
                    'version': version, 'cpes': versions_dict[version],
                    'product': product, 'vendor': vendor
                }
                st.success("Версия найдена")
                version_selected = True
            else:
                found_similar = False
                for v, cpes in versions_dict.items():
                    if version in v or v in version or v.startswith(version):
                        versions_found[comp] = {
                            'version': v, 'cpes': cpes,
                            'product': product, 'vendor': vendor
                        }
                        st.success("Версия найдена")
                        version_selected = True
                        found_similar = True
                        break
                if not found_similar and versions_dict:
                    first_version = list(versions_dict.keys())[0]
                    versions_found[comp] = {
                        'version': first_version,
                        'cpes': versions_dict[first_version],
                        'product': product, 'vendor': vendor
                    }
                    st.info(f"Использована версия: {first_version}")
                    version_selected = True
                elif not versions_dict and matches:
                    versions_found[comp] = {
                        'version': version,
                        'cpes': [c for c, v, p in matches],
                        'product': product, 'vendor': vendor
                    }
                    st.info("Версия не найдена в базе, используем все CPE")
                    version_selected = True
                elif not versions_dict and not matches:
                    st.warning(f"Компонент '{product}' не найден в базе")
                    versions_found[comp] = {
                        'version': None, 'cpes': [],
                        'product': product, 'vendor': vendor
                    }
                    version_selected = True

        elif version_list:
            display_versions = version_list[:30]
            version_options = ["-- Выберите версию --"] + display_versions + ["Другая версия..."]

            sel_label = st.selectbox(
                f"Версия для **{comp}**:",
                options=version_options,
                key=select_key,
                index=0
            )
            manual_version = st.text_input(
                f"Или введите версию для **{comp}** вручную:",
                placeholder="например: 3.9.0 (оставьте пустым, если выбрали выше)",
                key=input_key,
                value=""
            )

            if sel_label not in ("-- Выберите версию --", "Другая версия..."):
                versions_found[comp] = {
                    'version': sel_label,
                    'cpes': versions_dict[sel_label],
                    'product': product, 'vendor': vendor
                }
                st.success(f"Версия найдена: {sel_label}")
                version_selected = True
            elif manual_version and manual_version.strip():
                sel_ver = manual_version.strip()
                found = False
                if sel_ver in versions_dict:
                    versions_found[comp] = {
                        'version': sel_ver, 'cpes': versions_dict[sel_ver],
                        'product': product, 'vendor': vendor
                    }
                    st.success("Версия найдена")
                    version_selected = True
                    found = True
                else:
                    for v, cpes in versions_dict.items():
                        if sel_ver == v or sel_ver.startswith(v+".") or v.startswith(sel_ver+"."):
                            versions_found[comp] = {
                                'version': v, 'cpes': cpes,
                                'product': product, 'vendor': vendor
                            }
                            st.success("Версия найдена")
                            version_selected = True
                            found = True
                            break
                if not found:
                    versions_found[comp] = {
                        'version': sel_ver,
                        'cpes': [c for c, v, p in matches],
                        'product': product, 'vendor': vendor
                    }
                    st.warning(f"Версия '{sel_ver}' не найдена в базе")
                    version_selected = True
            else:
                versions_found[comp] = {
                    'version': None, 'cpes': [],
                    'product': product, 'vendor': vendor
                }

        if not version_selected and not version_list:
            if matches:
                versions_found[comp] = {
                    'version': None,
                    'cpes': [c for c, v, p in matches],
                    'product': product, 'vendor': vendor
                }
                st.info("Версии не найдены, используем все CPE")
            else:
                versions_found[comp] = {
                    'version': None, 'cpes': [],
                    'product': product, 'vendor': vendor
                }
                st.warning(f"Компонент '{product}' не найден в базе")

        importance_select = st.selectbox(
            f"Важность компонента **{comp}**:",
            options=["1", "2", "3", "4"],
            format_func=lambda x: {
                "1": "1 - Low (низкая)",
                "2": "2 - Medium (средняя)",
                "3": "3 - High (высокая)",
                "4": "4 - Critical (критическая)"
            }.get(x, x),
            key=imp_key,
            index=2
        )
        importance_label, importance_coeff = ASSET_IMPORTANCE.get(importance_select, ("medium", 0.5))
        component_importance[comp] = {'label': importance_label, 'coeff': importance_coeff}
        st.write(f"Коэффициент важности: **{importance_coeff}**")
        st.divider()

    st.session_state.component_versions = versions_found
    st.session_state.component_importance = component_importance

    col1, col2 = st.columns([3, 1])
    with col1:
        if st.button("Далее: Анализ", type="primary", use_container_width=True):
            has_unselected = any(
                v.get('version') is None and v.get('cpes') == []
                for v in versions_found.values()
            )
            if has_unselected:
                st.error("Выберите версию для всех компонентов!")
            else:
                st.session_state.step = 2
                st.rerun()
    with col2:
        if st.button("Назад", use_container_width=True):
            st.session_state.step = 0
            st.rerun()

    st.stop()

if st.session_state.step == 2:
    component_risks = []

    for comp in st.session_state.components:
        ver_info = st.session_state.component_versions.get(comp, {})
        selected_cpes = ver_info.get('cpes', [])
        imp_info = st.session_state.component_importance.get(comp, {'label': 'medium', 'coeff': 0.5})
        importance_label = imp_info['label']
        importance_coeff = imp_info['coeff']

        if not selected_cpes:
            component_risks.append({
                "component": comp, "max_risk": 0, "avg_risk": 0,
                "count": 0, "cve_risks": [],
                "importance": importance_label, "importance_coeff": importance_coeff
            })
            continue

        cves, cwes, capecs = extract_graph(selected_cpes)

        if not cves:
            component_risks.append({
                "component": comp, "max_risk": 0, "avg_risk": 0,
                "count": 0, "cve_risks": [],
                "importance": importance_label, "importance_coeff": importance_coeff
            })
            continue

        cve_risks = []
        for cve in cves:
            cve_cwes = list(getattr(cve, "hasWeakness", []))
            cvss = get_cvss(cve, cwes=cve_cwes)
            epss = get_epss_score(cve.name)

            if cvss is not None and epss is not None and epss > 0:
                rp = get_risk_percentile(cvss, epss)
                base_risk = (rp / 100) * 10 * importance_coeff if rp else cvss * epss * importance_coeff
            elif cvss is not None:
                base_risk = (cvss / 10) * importance_coeff
            elif epss is not None and epss > 0:
                base_risk = 5 * epss * importance_coeff
            else:
                base_risk = 0

            cwe_risks_list = [
                calculate_chain_risk(extract_cwe_id(cwe), base_risk)
                for cwe in cve_cwes
            ]
            cve_risk = max(cwe_risks_list) if cwe_risks_list else base_risk
            cve_risks.append({"cve": cve.name, "cvss": cvss, "epss": epss, "risk": cve_risk})

        risk_values = [cr["risk"] for cr in cve_risks]
        component_risks.append({
            "component": comp,
            "max_risk": max(risk_values) if risk_values else 0,
            "avg_risk": mean(risk_values) if risk_values else 0,
            "count": len(cve_risks),
            "cve_risks": cve_risks,
            "importance": importance_label,
            "importance_coeff": importance_coeff
        })

    st.session_state.analysis_results = component_risks
    st.session_state.step = 3
    st.rerun()

if st.session_state.step == 3:
    cr = st.session_state.analysis_results

    st.markdown(
        '<div class="results-header"><h1>Результаты оценки рисков</h1></div>',
        unsafe_allow_html=True
    )

    if cr:
        total = sum(c["count"] for c in cr)
        max_all = max((c["max_risk"] for c in cr if c["count"] > 0), default=0)
        vuln_factor = math.log(1 + total)
        app_risk = max_all + vuln_factor

        risk_lvl = risk_level(app_risk)
        risk_class = {
            "Критический": "risk-critical",
            "Высокий": "risk-high",
            "Средний": "risk-medium",
            "Низкий": "risk-low"
        }.get(risk_lvl, "risk-medium")
        risk_icon = {
            "Критический": "🔴", "Высокий": "🟠",
            "Средний": "🟡", "Низкий": "🟢"
        }.get(risk_lvl, "🔵")

        st.markdown(f"""
        <div class="risk-result {risk_class}">
            <span style="font-size:1.2em;">{risk_icon}</span>
            <strong>Риск приложения: {round(app_risk, 2)} из {MAX_RISK_APP}</strong>
            <span style="margin-left:15px;">— {risk_lvl}</span>
        </div>
        """, unsafe_allow_html=True)

        df = pd.DataFrame([{
            "Компонент": c["component"],
            "Важность": f"{c['importance']} ({c['importance_coeff']})",
            "Max риск": f"{c['max_risk']:.2f}",
            "Avg риск": f"{c['avg_risk']:.2f}"
        } for c in cr])
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.markdown(f"""
        <div style="background:#f8f9fa;padding:15px;border-radius:8px;margin:20px 0;">
            <p style="margin:5px 0;"><strong>Всего уязвимостей (CVE):</strong> {total}</p>
            <p style="margin:5px 0;"><strong>Максимальный риск компонента:</strong> {max_all:.4f}</p>
            <p style="margin:5px 0;"><strong>Фактор количества:</strong> {vuln_factor:.4f}</p>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Новый анализ", type="secondary", use_container_width=True):
                st.session_state.step = 0
                st.session_state.components = []
                st.session_state.component_versions = {}
                st.session_state.analysis_results = []
                st.rerun()
        with col2:
            if st.button("Детали анализа", type="primary", use_container_width=True):
                st.session_state.step = 4
                st.rerun()
        with col3:
            csv_data = df.to_csv(index=False, sep=';', decimal=',')
            st.download_button(
                label="Скачать CSV",
                data=csv_data,
                file_name="risk_assessment_results.csv",
                mime="text/csv",
                use_container_width=True
            )

    st.stop()

if st.session_state.step == 4:
    st.markdown(
        '<div class="results-header"><h1>Детали анализа</h1></div>',
        unsafe_allow_html=True
    )
    cr = st.session_state.analysis_results

    if st.button("Назад к результатам", type="secondary"):
        st.session_state.step = 3
        st.rerun()

    st.divider()

    component_names = [c["component"] for c in cr if c["count"] > 0]

    if component_names:
        selected_comp = st.selectbox(
            "Выберите компонент для просмотра деталей:",
            options=component_names
        )
        st.divider()

        comp_data = next((c for c in cr if c["component"] == selected_comp), None)

        if comp_data and comp_data["cve_risks"]:
            st.markdown(f"### {selected_comp}")

            ver_info = st.session_state.component_versions.get(selected_comp, {})
            imp_info = st.session_state.component_importance.get(
                selected_comp, {'label': 'medium', 'coeff': 0.5}
            )

            col1, col2, col3 = st.columns(3)
            with col1: st.metric("Версия", ver_info.get('version', 'N/A'))
            with col2: st.metric("Важность", f"{imp_info['label']} ({imp_info['coeff']})")
            with col3: st.metric("Всего CVE", comp_data["count"])

            st.markdown(
                f"**Max риск:** {comp_data['max_risk']:.4f} | "
                f"**Avg риск:** {comp_data['avg_risk']:.4f}"
            )
            st.divider()

            st.markdown("### Уязвимости (CVE)")
            cve_data = [{
                "CVE": cve["cve"],
                "CVSS": f"{cve['cvss']:.1f}" if cve['cvss'] else "N/A",
                "EPSS": f"{cve['epss']:.4f}" if cve['epss'] else "N/A",
                "Риск": f"{cve['risk']:.4f}"
            } for cve in sorted(comp_data["cve_risks"], key=lambda x: x["risk"], reverse=True)]
            st.dataframe(pd.DataFrame(cve_data), use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("### Детальный расчёт риска")

            for idx, cve in enumerate(
                sorted(comp_data["cve_risks"], key=lambda x: x["risk"], reverse=True)[:10], 1
            ):
                with st.expander(f"CVE {idx}: {cve['cve']} (риск: {cve['risk']:.4f})", expanded=False):
                    st.markdown(f"""
**CVSS Score:** {cve['cvss'] if cve['cvss'] else 'N/A'}

**EPSS Score:** {cve['epss'] if cve['epss'] else 'N/A'}

**Базовый риск:** {(cve['cvss'] / 10) * imp_info['coeff'] if cve['cvss'] else 'N/A'}

**Коэффициент важности:** {imp_info['coeff']}

**Итоговый риск:** {cve['risk']:.4f}
                    """)
        else:
            st.info("Для выбранного компонента уязвимости не найдены")
    else:
        st.warning("Нет данных для отображения деталей")

    st.stop()

st.divider()
st.markdown(
    "<div style='text-align:center;color:gray;font-size:0.9em;'>"
    "ВКР 10.03.01 «Информационная безопасность»"
    "</div>",
    unsafe_allow_html=True
)
