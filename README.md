# Экспертная система оценки рисков безопасности программного обеспечения

## Описание проекта

Проект представляет собой экспертную систему для автоматизированной оценки рисков безопасности приложений на основе анализа уязвимостей (CVE), слабостей (CWE), шаблонов атак (CAPEC) и конфигураций (CPE).

Система использует онтологию безопасности (OWL) для представления знаний и логического вывода, а также интегрируется с внешними API (NVD, EPSS) для получения актуальных данных об уязвимостях.

---

## Возможности системы

- **Загрузка данных** из NVD API (CVE, CPE), CWE/CAPEC XML
- **Построение OWL-онтологии** безопасности с импортом данных
- **Логический вывод** с использованием OWL reasoner (HermiT) для выявления транзитивных связей CWE
- **Расчет риска** на основе CVSS, EPSS, цепочек CWE и важности компонента
- **Нормализация риска** через эмпирическое распределение (референсные перцентили)
- **Веб-интерфейс** для интерактивного анализа компонентов с детальным отчётом

---

## Структура проекта

> **Примечание:** Большие файлы данных (CSV, XML, OWL) не включены в репозиторий и загружаются отдельно. Ссылки на скачивание указаны в соответствующих `.md` файлах.

```
ontology-for-assessing-the-information-security-risk-of-applications/
├── data_processing/                      # Модуль загрузки и обработки данных
│   ├── csv_files_ready/                  # Готовые CSV файлы
│   │   ├── all_cvs_data.md               # Ссылка на скачивание CSV
│   │                
│   ├── data loaders/                     # Скрипты загрузки данных
│   │   ├── cve_api_loader.py             # Загрузка CVE из NVD API
│   │   ├── cpe_api_loader.py             # Загрузка CPE из NVD API
│   │   ├── cwe_data_processing.py        # Обработка CWE XML
│   │   ├── capec_data_processing.py      # Обработка CAPEC XML
│   │   ├── cve_data_processing.py        # Сопоставление CPE-CVE
│   │   └── cpe_data_processing.py        # Фильтрация CPE
│   └── xml_data_ready/
│       └── xml_data.md                   # Ссылка на скачивание XML
│
├── owl_files_processing/                 # Модуль построения онтологии
│   ├── owl_files/
│   │   ├── security_ontology_structure.owl   # Структура онтологии
│   │   └── security_ontology_full.md         # Ссылка на скачивание OWL полной онтологии
│   └── scripts_for_create_ontology/
│       ├── create_ontology_structure.py  # Создание структуры онтологии
│       └── import_data_in_ontology.py    # Импорт данных в онтологию
│
├── scripts_for_create_reasoning/         # Модуль логического вывода и расчета риска
│   ├── owl_reasoning_build_cwe_chains.py # Построение цепочек CWE через reasoner
│   ├── build_risk_reference.py           # Построение референсного распределения
│   ├── risk_calculation.py               # Главный модуль расчета риска
│   ├── risk_calculation_web.py           # Веб-версия расчета риска
│   ├── risk_calculation_preparation_data/
│   │   ├── cwe_chains.json               # Кэш цепочек CWE
│   │   └── risk_reference_distribution.json  # Референсное распределение
│   └── web_interface/                    # Веб-интерфейс (Streamlit)
│       ├── app.py                        # Основное приложение
│       ├── styles.css                    # Файл стилей
│       ├── requirements.txt              # Зависимости
│       └── README.md                     # Документация веб-интерфейса
│
├── .local.env                            # [создаётся] Переменные окружения
├── .venv/                                # [создаётся] Виртуальное окружение
├── requirements.txt                      # Основные зависимости
└── README.md                             # Этот файл
```

---

## Установка

### Требования

- Python 3.10+
- Java (для OWL reasoner HermiT)
- 8+ GB RAM (рекомендуется 16 GB для работы с полной онтологией)

### Установка зависимостей

```bash
# Создание виртуального окружения
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux

# Установка зависимостей
pip install -r requirements.txt
```

### Файл зависимостей (requirements.txt)

```
pandas>=2.0.0
owlready2>=0.40.0
python-dotenv>=1.0.0
tqdm>=4.65.0
deep-translator>=1.9.0
streamlit>=1.28.0
```

---

## Конфигурация

Создайте файл `.local.env` в корневой директории проекта:

```env
# ============================================
# ИСТОЧНИКИ ДАННЫХ
# ============================================

# CVE данные
CVE_OUTPUT=/path/to/data_processing/csv_files/cve_all.csv
CVE_PROCESSING_OUTPUT=/path/to/data_processing/csv_files/cve_all_done.csv

# CPE данные
CPE_OUTPUT=/path/to/data_processing/csv_files/cpe_all.csv

# CWE данные
CWE_OUTPUT_CSV=/path/to/data_processing/csv_files/cwe_all.csv

# CAPEC данные
CAPEC_OUTPUT=/path/to/data_processing/csv_files/capec_all.csv

# ============================================
# ОНТОЛОГИЯ
# ============================================

ONTO_IRI=http://vkr/security_ontology
ONTO_PATH=/path/to/owl_files_processing/owl_files/security_ontology_full.owl
ONTO_OUTPUT=/path/to/owl_files_processing/owl_files/security_ontology_full.owl

# ============================================
# CWE ЦЕПОЧКИ (результат работы reasoner)
# ============================================

CWE_CHAINS_OUTPUT=/path/to/scripts_for_create_reasoning/risk_calculation_preparation_data/cwe_chains.json

# ============================================
# РЕФЕРЕНСНОЕ РАСПРЕДЕЛЕНИЕ РИСКОВ
# ============================================

RISK_REFERENCE_OUTPUT=/path/to/scripts_for_create_reasoning/risk_calculation_preparation_data/risk_reference_distribution.json
```

---

## Использование

### Этап 1: Загрузка данных

```bash
# Загрузка CVE из NVD API
python "data_processing/data loaders/cve_api_loader.py"

# Загрузка CPE из NVD API
python "data_processing/data loaders/cpe_api_loader.py"

# Обработка CWE XML
python "data_processing/data loaders/cwe_data_processing.py"

# Обработка CAPEC XML
python "data_processing/data loaders/capec_data_processing.py"

# Сопоставление CPE-CVE
python "data_processing/data loaders/cve_data_processing.py"

# Фильтрация CPE
python "data_processing/data loaders/cpe_data_processing.py"
```

**Результат:** CSV файлы в `data_processing/csv_files/`

---

### Этап 2: Построение онтологии

```bash
# Создание структуры онтологии
python owl_files_processing/scripts_for_create_ontology/create_ontology_structure.py

# Импорт данных в онтологию
python owl_files_processing/scripts_for_create_ontology/import_data_in_ontology.py
```

**Результат:** `security_ontology_full.owl` в `owl_files_processing/owl_files/`

---

### Этап 3: Построение CWE цепочек (OWL Reasoning)

```bash
python scripts_for_create_reasoning/owl_reasoning_build_cwe_chains.py
```

**Результат:** `cwe_chains.json` — транзитивные связи между CWE

**Описание:** Скрипт создает транзитивное свойство `CanPrecede` и использует OWL reasoner HermiT для вывода полных цепочек CWE.

---

### Этап 4: Построение референсного распределения рисков

```bash
python scripts_for_create_reasoning/build_risk_reference.py
```

**Результат:** `risk_reference_distribution.json` — отсортированный массив значений CVSS × EPSS

**Описание:** Скрипт загружает CVE с CVSS, запрашивает EPSS из FIRST API, вычисляет риски и строит эмпирическое распределение для нормализации оценок.

---

### Этап 5: Расчет риска для компонентов приложения

#### Консольный режим

```bash
python scripts_for_create_reasoning/risk_calculation.py
```

#### Веб-интерфейс (рекомендуется)

```bash
cd scripts_for_create_reasoning/web_interface
streamlit run app.py
```

**Веб-интерфейс доступен по адресу:** http://localhost:8501

---

## Веб-интерфейс

### Возможности

- **Пошаговый анализ** — ввод компонентов, выбор версий, оценка важности
- **Визуализация рисков** — цветная индикация уровней риска
- **Детальный отчёт** — информация по каждой уязвимости (CVE, CVSS, EPSS, риск)
- **Экспорт данных** — выгрузка результатов в CSV

### Запуск

```bash
cd scripts_for_create_reasoning/web_interface
streamlit run app.py
```

### Этапы анализа

1. **Ввод компонентов** — названия и версии (например: `python 3.9, google chrome 90.0`)
2. **Выбор версий** — выбор из базы или ручной ввод
3. **Оценка важности** — коэффициент для каждого компонента
4. **Результаты** — таблица рисков и общий риск приложения
5. **Детали анализа** — подробная информация по уязвимостям

Подробнее: [scripts_for_create_reasoning/web_interface/README.md](scripts_for_create_reasoning/web_interface/README.md)

---

## Математическая модель

### Формула расчета риска для CVE

```
R_CVE = (P_percentile / 100) × 10 × K_importance × F_chain
```

где:
- `P_percentile` — перцентиль риска в референсном распределении (0-100)
- `K_importance` — коэффициент важности компонента (0.25-1.0)
- `F_chain` — множитель цепочки CWE (≥1.0)

### Формула учета цепочки CWE

```
R_chain = R_base × (1 + decay^1 + decay^2 + ... + decay^n)
```

где `decay = 0.5` — коэффициент затухания.

### Формула риска приложения

```
R_app = max(R_component_i) + log(1 + N_CVE)
```

### Уровни риска

| Диапазон | Уровень | Описание |
|----------|---------|----------|
| 0-6 | Низкий | Риск приемлем |
| 6-12 | Средний | Требуется планирование исправлений |
| 12-18 | Высокий | Необходимы срочные меры |
| 18-24 | Критический | Немедленное вмешательство |

---

## Источники данных

| Тип данных | Источник | API/Формат |
|------------|----------|------------|
| CVE | NVD (NIST) | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| CPE | NVD (NIST) | https://services.nvd.nist.gov/rest/json/cpes/2.0 |
| EPSS | FIRST | https://api.first.org/data/v1/epss |
| CWE | MITRE | cwec_v4.19.1.xml |
| CAPEC | MITRE | capec_v3.9.xml |

---

## Онтология безопасности

### Классы

- `WebApplication` — анализируемое приложение
- `Component` — программный компонент
- `CPE` — идентификатор конфигурации
- `CVE` — уязвимость
- `CWE` — слабость
- `CAPEC` — шаблон атаки

### Объектные свойства

| Свойство | Домен | Диапазон | Описание |
|----------|-------|----------|----------|
| `usesComponent` | WebApplication | Component | Приложение использует компонент |
| `mappedToCPE` | Component | CPE | Компонент сопоставлен с CPE |
| `affects` | CVE | CPE | Уязвимость влияет на CPE |
| `hasWeakness` | CVE | CWE | Уязвимость имеет слабость |
| `exploitedBy` | CWE | CAPEC | Слабость эксплуатируется атакой |
| `CanPrecede` | CWE | CWE | Слабость может предшествовать другой (транзитивное) |

---

## Архитектура системы

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA LAYER (Загрузка данных)                 │
│  NVD API → CVE, CPE  │  CWE/CAPEC XML → CSV                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ONTOLOGY LAYER (Построение онтологии)        │
│  create_ontology_structure.py  →  import_data_in_ontology.py    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    REASONING LAYER (Логический вывод)           │
│  owl_reasoning_build_cwe_chains.py (HermiT Reasoner)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    REFERENCE LAYER (Эталонное распределение)    │
│  build_risk_reference.py (CVSS × EPSS)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CALCULATION LAYER (Расчет риска)             │
│  risk_calculation.py (CLI)  │  risk_calculation_web.py (Web)   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER (Веб-интерфейс)           │
│  Streamlit Dashboard → Интерактивный анализ и отчёты            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Лицензия

Проект создан в образовательных целях.

---

## Приложения

### A. Ссылки на большие файлы

Большие файлы проекта размещены на Яндекс.Диске:

- [CSV файлы с данными](data_processing/csv_files_ready/all_cvs_data.md)
- [XML файлы CWE/CAPEC](data_processing/xml_data_ready/xml_data.md)
- [OWL онтология](owl_files_processing/owl_files/security_ontology_full.md)

### B. Примеры запросов

**Запрос CVE из NVD API:**
```bash
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=0&resultsPerPage=2000"
```

**Запрос EPSS из FIRST API:**
```bash
curl "https://api.first.org/data/v1/epss?cve=CVE-2021-3177"
```

### C. Полезные ссылки

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [EPSS Documentation](https://www.first.org/epss/faq)
- [OWL 2 Specification](https://www.w3.org/TR/owl2-overview/)
- [Owlready2 Documentation](https://owlready2.readthedocs.io/)
- [HermiT Reasoner](http://www.hermit-reasoner.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)
