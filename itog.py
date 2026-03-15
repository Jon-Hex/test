import os
import vt
import json
import pandas as pd
import matplotlib.pyplot as plt

api_key = os.environ.get("VT_API_KEY")

if not api_key:
    raise ValueError("API ключ VirusTotal не найден! Установите переменную окружения VT_API_KEY.")


# Читаем JSON-файл alerts-only
with open('alerts-only.json', 'r') as f:
    data = json.load(f)

# Превращаем в плоскую таблицу (нормализация)
# В дампах Wireshark данные обычно лежат в ключе '_source' -> 'layers'
df = pd.json_normalize(data)

# Пример анализа: топ-5 IP-отправителей
# Названия колонок зависят от структуры JSON (например, '_source.layers.ip.ip_src')

print("--- Топ-5 посещенных хостов (HTTP) ---")
if 'http.hostname' in df.columns:
    print(df['http.hostname'].value_counts().head())

print("\n--- Топ-5 URL-адресов ---")
if 'http.url' in df.columns:
    print(df['http.url'].value_counts().head())
else:
    print("Колонки для анализа не найдены. Проверьте имена в выводе выше.")

print("\n--- Топ-5 категорий угроз (Alert Category) ---")
if 'alert.category' in df.columns:
    print(df['alert.category'].value_counts().head())
    top_5_threats = df['alert.category'].value_counts().head(5)
    top_5_threats.to_csv('top_5_threats.csv', header=['count'])
    top_5_threats.to_json('top_5_threats.json', force_ascii=False, indent=4)

print("\n--- Распределение по протоколам ---")
if 'proto' in df.columns:
    print(df['proto'].value_counts())

print("\n--- Критические алерты (Severity 1) ---")

if 'alert.severity' in df.columns:
    # Выбираем только те строки, где уровень опасности высокий (например, 1)
    critical_alerts = df[df['alert.severity'] == 1]
    if not critical_alerts.empty:
        print(critical_alerts[['alert.signature', 'src_ip', 'dest_ip']].head())
    else:
        print("Критических угроз не обнаружено.")

# Рисуем круговую диаграмму категорий угроз
if 'alert.category' in df.columns:
    df['alert.category'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Распределение типов угроз')
    plt.ylabel('') # Убираем лишнюю подпись
    plt.savefig('threats_pie_chart.png', dpi=300)
    plt.show()

    print("\n--- IP-адреса попыток утечки информации (6 событий) ---")


df['alert.category'].value_counts().plot(kind='barh')
plt.title('Топ категорий угроз')
plt.savefig('full_analysis_report.png') 
plt.show()


# Фильтруем таблицу по нужной категории
leak_data = df[df['alert.category'] == 'Attempted Information Leak']

# Выводим IP отправителя и получателя для этих строк
if not leak_data.empty:
    # Выбираем колонки с IP (проверьте их названия, обычно это src_ip и dest_ip)
    result = leak_data[['src_ip', 'dest_ip']].value_counts().reset_index()
    print(result)
else:
    print("События 'Attempted Information Leak' не найдены.")

vt_check_list = leak_data['src_ip'].unique()[:2].tolist()

# Печатаем результат 
print("Список IP для проверки в VirusTotal:")
print(vt_check_list)

#print(leak_data.head(2))
#print(leak_data.head(2).T)


print("\n--- Анализ DNS-запросов ---")

# Проверяем наличие колонки с именами хостов (в разных дампах они зовутся по-разному)
dns_cols = ['dns.qry.name', 'query', 'dns_query']
found_dns_col = next((c for c in dns_cols if c in df.columns), None)

if found_dns_col:
    print(f"Топ-10 запрашиваемых доменов:")
    print(df[found_dns_col].value_counts().head(10))
else:
    # Если прямой колонки нет, фильтруем по порту 53 (стандарт DNS)
    if 'dest_port' in df.columns:
        dns_packets = df[df['dest_port'] == 53]
        print(f"Найдено пакетов на порт 53 (DNS): {len(dns_packets)}")
        # Если есть колонка с именами, выводим их
        if 'http.hostname' in df.columns: # Иногда DNS-имена попадают сюда
             print(dns_packets['http.hostname'].value_counts())
    else:
        print("Колонки DNS не найдены. Попробуйте поискать 'dns' в списке df.columns.tolist()")


script_dir = os.path.dirname(__file__)

file_path = os.path.join(script_dir, "alerts-only.json")

print(f"Файл {file_path} найден, отправляю на проверку...")
with vt.Client(api_key) as client:
    with open(file_path, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=True)
        print("Analysis ID:", analysis.id)
        print("Status:", analysis.status)
        print("Stats:", analysis.stats)



vt_results = [] # Будем сохранять данные по каждому IP

# Проходим циклом по сформированному списку из топ 2-х IP
with vt.Client(api_key) as client:
    for ip in vt_check_list:
        print(f"\n--- Проверка IP: {ip} ---")
        try:
            # Получаем отчет по конкретному IP-адресу
            analysis = client.get_object(f"/ip_addresses/{ip}")
            
            # Выводим результаты (сколько антивирусов считают его вредоносным)
            stats = analysis.last_analysis_stats

            vt_results.append({
                "ip": ip,
                "malicious": stats.get('malicious', 0),
                "undetermined": stats.get('undetermined', 0),
                "harmless": stats.get('harmless', 0),
                "suspicious": stats.get('suspicious', 0),
                "timeout": stats.get('timeout', 0),
                "undetected": stats.get('undetected', 0)
            })

            print(f"Результаты: {stats}")
            print(f"Вредоносных срабатываний: {stats['malicious']}")

            if stats['malicious'] > 0:
                print(f"⚠️ ВНИМАНИЕ: IP {ip} признан ОПАСНЫМ!")
            else:
                print(f"✅ IP {ip} чист.")
            
        except vt.error.APIError as e:
            print(f"Ошибка API для {ip}: {e}")

with open('vt_results.json', 'w', encoding='utf-8') as f:
    json.dump(vt_results, f, ensure_ascii=False, indent=4)

df_vt = pd.DataFrame(vt_results)
df_vt.to_csv('vt_results.csv', index=False)

df_old =pd.DataFrame(vt_results)
df_combined = pd.concat([df_old, df_vt], axis=0, ignore_index=True)
df_combined.to_csv('top_5_threats.csv', index=False, encoding='utf-8-sig')

with open('top_5_threats.json', 'r', encoding='utf-8') as f:
    report_data = json.load(f)
report_data['vt_analysis_results'] = vt_results 

with open('top_5_threats.json', 'w', encoding='utf-8') as f:
    json.dump(report_data, f, ensure_ascii=False, indent=4)


print("\n[+] Отчеты VirusTotal сохранены в vt_results.json и vt_results.csv")


