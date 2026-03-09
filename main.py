# Список библиотек
import json
import datetime
import time
import os
import hashlib
from collections import Counter
from dotenv import load_dotenv
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import IP, TCP, UDP, ICMP, DNS
from scapy.utils import PcapReader

# Загружаем ключ из .env
load_dotenv()


class VirusTotalAPI:
    # Класс для работы с VirusTotal API
    
    def __init__(self):
        # Инициализация с ключом из переменных окружения
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.cache_file = "virustotal_cache.json"
        self.cache = self._load_cache()
        
        # Для rate limiting
        self.request_timestamps = []
    
    def _load_cache(self):
        # Загрузка кеша результатов
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_cache(self):
        # Сохранение кеша
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def _wait_for_rate_limit(self):
        # Ожидание соблюдения rate limit (4 запроса в минуту)
        current_time = time.time()
        self.request_timestamps = [t for t in self.request_timestamps 
                                   if current_time - t < 60]
        
        if len(self.request_timestamps) >= 4:
            oldest = min(self.request_timestamps)
            wait_time = 60 - (current_time - oldest)
            if wait_time > 0:
                print(f"Лимит запросов. Ожидание {wait_time:.1f} сек...")
                time.sleep(wait_time)
        
        self.request_timestamps.append(time.time())
    
    def get_file_hash(self, filepath):
        # Вычисление SHA-256 хеша файла
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def upload_file(self, filepath):
        # Загрузка файла на VirusTotal для анализа
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath) / (1024 * 1024)
        
        print(f"\nЗагрузка файла на VirusTotal")
        print(f"Размер: {filesize:.2f} MB")
        
        # Проверяем размер (бесплатный лимит 32MB)
        if filesize > 32:
            print(f"Файл больше 32MB (бесплатный лимит)")
            return None
        
        url = "https://www.virustotal.com/api/v3/files"
        
        self._wait_for_rate_limit()
        
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (filename, f)}
                response = requests.post(url, headers=self.headers, files=files)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                print(f"Файл загружен. ID анализа: {analysis_id}")
                
                # Ждем завершения анализа
                return self._get_analysis_results(analysis_id)
            else:
                print(f"Ошибка загрузки: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Ошибка: {e}")
            return None
    
    def _get_analysis_results(self, analysis_id):
        # Получение результатов анализа
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        print(f"Ожидание результатов анализа...")
        
        for attempt in range(10):
            self._wait_for_rate_limit()
            
            try:
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get('data', {}).get('attributes', {}).get('status')
                    
                    if status == 'completed':
                        stats = data.get('data', {}).get('attributes', {}).get('stats', {})
                        
                        # Получаем детальные результаты
                        results = data.get('data', {}).get('attributes', {}).get('results', {})
                        malicious_names = []
                        for av, result in results.items():
                            if result.get('category') == 'malicious':
                                malicious_names.append(av)
                        
                        return {
                            'malicious': stats.get('malicious', 0),
                            'suspicious': stats.get('suspicious', 0),
                            'harmless': stats.get('harmless', 0),
                            'undetected': stats.get('undetected', 0),
                            'malicious_names': malicious_names[:10]
                        }
                    else:
                        print(f"Статус: {status}, ожидание...")
                        time.sleep(10)
                else:
                    return None
                    
            except Exception as e:
                print(f"Ошибка: {e}")
                return None
        
        print("Таймаут ожидания")
        return None
    
    def check_file(self, filepath):
        # Проверка файла через VirusTotal
        if not os.path.exists(filepath):
            return {"error": "File not found"}
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath) / (1024 * 1024)
        
        print(f"\n{'='*60}")
        print(f"VirusTotal анализ")
        print(f"{'='*60}")
        print(f"Файл: {filename}")
        print(f"Размер: {filesize:.2f} MB")
        
        # Вычисляем хеш
        file_hash = self.get_file_hash(filepath)
        print(f"SHA-256: {file_hash[:16]}...")
        
        # Проверяем кеш
        if file_hash in self.cache:
            print(f"Результат из кеша")
            cached = self.cache[file_hash]
            self._print_results(cached)
            return cached
        
        # Проверяем по хешу в VirusTotal
        self._wait_for_rate_limit()
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                # Получаем имена антивирусов
                results = attributes.get('last_analysis_results', {})
                malicious_names = []
                for av, result in results.items():
                    if result.get('category') == 'malicious':
                        malicious_names.append(av)
                
                result_data = {
                    'filename': filename,
                    'hash': file_hash,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'malicious_names': malicious_names[:10],
                    'source': 'database'
                }
                
                # Сохраняем в кеш
                self.cache[file_hash] = result_data
                self._save_cache()
                
                self._print_results(result_data)
                return result_data
                
            elif response.status_code == 404:
                print(f"\nФайл не найден в базе VirusTotal")
                print(f"Попытка загрузить файл для анализа...")
                
                # Загружаем файл
                upload_result = self.upload_file(filepath)
                
                if upload_result:
                    result_data = {
                        'filename': filename,
                        'hash': file_hash,
                        'malicious': upload_result.get('malicious', 0),
                        'suspicious': upload_result.get('suspicious', 0),
                        'harmless': upload_result.get('harmless', 0),
                        'undetected': upload_result.get('undetected', 0),
                        'malicious_names': upload_result.get('malicious_names', []),
                        'source': 'upload'
                    }
                    
                    # Сохраняем в кеш
                    self.cache[file_hash] = result_data
                    self._save_cache()
                    
                    self._print_results(result_data)
                    return result_data
                else:
                    return {'error': 'Upload failed'}
            else:
                print(f"\nОшибка API: {response.status_code}")
                return {'error': f'API Error: {response.status_code}'}
                
        except Exception as e:
            print(f"\nОшибка: {e}")
            return {'error': str(e)}
    
    def _print_results(self, result):
        # Вывод результатов в консоль
        print(f"\nРезультаты VirusTotal:")
        print(f"Вредоносных:      {result.get('malicious', 0)}")
        print(f"Подозрительных:   {result.get('suspicious', 0)}")
        print(f"Безвредных:       {result.get('harmless', 0)}")
        print(f"Неопределенных:   {result.get('undetected', 0)}")
        
        if result.get('malicious', 0) > 0:
            print(f"\nОбнаружено антивирусами:")
            for name in result.get('malicious_names', [])[:10]:
                print(f"- {name}")
        else:
            print(f"\nФайл чистый (ни один антивирус не обнаружил угроз)")


class PcapAnalyzer:
    # Анализатор pcap файлов
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'syn_packets': 0
        }
        self.aggregated = {
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'ports': Counter(),
            'syn_src': Counter(),
            'dns_queries': Counter()
        }
        self.threats = []
    
    def analyze(self):
        # Анализ pcap файла
        print(f"\n{'='*60}")
        print("Анализ PCAP файла")
        print(f"{'='*60}")
        
        if not os.path.exists(self.pcap_file):
            print(f"Файл {self.pcap_file} не найден!")
            return
        
        start_time = time.time()
        packet_count = 0
        
        print(f"Файл: {self.pcap_file}")
        
        try:
            with PcapReader(self.pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1
                    
                    if packet_count % 100000 == 0:
                        elapsed = time.time() - start_time
                        print(f"Обработано {packet_count:,} пакетов... ({elapsed:.1f} сек)")
                    
                    self._parse_packet(pkt)
            
            elapsed = time.time() - start_time
            
            print(f"\Статистика:")
            print(f"Всего пакетов:     {packet_count:,}")
            print(f"IP пакетов:        {self.stats['ip_packets']:,}")
            print(f"TCP пакетов:       {self.stats['tcp_packets']:,}")
            print(f"SYN пакетов:       {self.stats['syn_packets']:,}")
            print(f"Уникальных IP:     {len(self.aggregated['src_ips'])}")
            print(f"DNS запросов:      {len(self.aggregated['dns_queries'])}")
            print(f"Время анализа:     {elapsed:.1f} сек")
            
            self._find_threats()
            
        except Exception as e:
            print(f"Ошибка: {e}")
    
    def _parse_packet(self, pkt):
        # Разбор пакета
        if IP not in pkt:
            return
        
        ip_layer = pkt[IP]
        self.stats['ip_packets'] += 1
        self.aggregated['src_ips'][ip_layer.src] += 1
        
        if TCP in pkt:
            self.stats['tcp_packets'] += 1
            tcp = pkt[TCP]
            self.aggregated['ports'][tcp.dport] += 1
            
            if 'S' in str(tcp.flags):
                self.stats['syn_packets'] += 1
                self.aggregated['syn_src'][ip_layer.src] += 1
        
        elif UDP in pkt and DNS in pkt and pkt[DNS].qr == 0:
            try:
                dns_query = pkt[DNS].qd.qname.decode().rstrip('.')
                self.aggregated['dns_queries'][dns_query] += 1
            except:
                pass
    
    def _find_threats(self):
        # Поиск угроз в трафике
        print(f"\n{'='*60}")
        print("Поиск угроз в трафике")
        print(f"{'='*60}")
        
        # SYN сканирование
        syn_found = False
        for ip, count in self.aggregated['syn_src'].most_common(10):
            if count >= 10:
                self.threats.append({
                    'type': 'SYN_SCAN',
                    'src_ip': ip,
                    'count': count,
                    'severity': 'HIGH' if count > 100 else 'MEDIUM',
                })
                print(f"SYN сканирование от {ip} ({count} пакетов)")
                syn_found = True
        
        if not syn_found:
            print(f"SYN сканирование не обнаружено")
        
        # Опасные порты
        dangerous_ports = {22: 'SSH', 23: 'TELNET', 445: 'SMB', 3389: 'RDP'}
        ports_found = False
        for port, count in self.aggregated['ports'].most_common(10):
            if port in dangerous_ports and count > 5:
                self.threats.append({
                    'type': 'DANGEROUS_PORT',
                    'port': port,
                    'service': dangerous_ports[port],
                    'count': count,
                    'severity': 'MEDIUM',
                })
                print(f"Порт {port} ({dangerous_ports[port]}): {count} подключений")
                ports_found = True
        
        if not ports_found:
            print(f"Опасные порты не обнаружены")
        
        print(f"\nНайдено угроз в трафике: {len(self.threats)}")


def create_visualizations(vt_result, pcap):
    # Создание графиков
    print(f"\n{'='*60}")
    print("Создание графиков")
    print(f"{'='*60}")
    
    # График 1: Результаты VirusTotal
    if vt_result and 'malicious' in vt_result:
        plt.figure(figsize=(10, 6))
        
        categories = ['Вредоносные', 'Подозрительные', 'Безвредные']
        values = [
            vt_result.get('malicious', 0),
            vt_result.get('suspicious', 0),
            vt_result.get('harmless', 0)
        ]
        colors = ['red', 'orange', 'green']
        
        bars = plt.bar(categories, values, color=colors)
        plt.title('Результаты VirusTotal')
        plt.ylabel('Количество антивирусов')
        
        # Добавляем значения на столбцы
        for bar, val in zip(bars, values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(val), ha='center', va='bottom')
        
        # Добавляем имена антивирусов если есть
        if vt_result.get('malicious_names'):
            names_text = '\n'.join(vt_result['malicious_names'][:5])
            plt.text(0.95, 0.95, f"Обнаружили:\n{names_text}", 
                    transform=plt.gca().transAxes,
                    verticalalignment='top',
                    horizontalalignment='right',
                    bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig('virustotal_results.png', dpi=150)
        plt.close()
        print("virustotal_results.png создан")
    
    # График 2: Топ источников трафика
    if pcap.aggregated['src_ips']:
        plt.figure(figsize=(12, 6))
        top_ips = dict(pcap.aggregated['src_ips'].most_common(10))
        
        plt.bar(range(len(top_ips)), list(top_ips.values()), color='steelblue')
        plt.xticks(range(len(top_ips)), list(top_ips.keys()), rotation=45)
        plt.title('Топ-10 источников трафика')
        plt.xlabel('IP адрес')
        plt.ylabel('Количество пакетов')
        
        # Добавляем значения
        for i, (ip, count) in enumerate(top_ips.items()):
            plt.text(i, count + 5, str(count), ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('top_sources.png', dpi=150)
        plt.close()
        print("top_sources.png создан")
    
    # График 3: Типы угроз
    if pcap.threats:
        plt.figure(figsize=(10, 6))
        threat_types = Counter([t['type'] for t in pcap.threats])
        
        bars = plt.bar(range(len(threat_types)), list(threat_types.values()), 
                      color=['red', 'orange', 'purple'])
        plt.xticks(range(len(threat_types)), list(threat_types.keys()), rotation=45)
        plt.title('Типы обнаруженных угроз')
        plt.ylabel('Количество')
        
        # Добавляем значения
        for i, (typ, count) in enumerate(threat_types.items()):
            plt.text(i, count + 0.1, str(count), ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('threat_types.png', dpi=150)
        plt.close()
        print("threat_types.png создан")


def main():
    # Главная функция
    print(f"\n{'='*70}")
    print("Программа анализа угроз")
    print(f"{'='*70}")
    print(f"Время запуска: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Файл для проверки
    file_to_check = r"C:\Users\1\Downloads\Перечень VLAN.pdf"
    
    # PCAP файл для анализа
    pcap_file = "20180323_logs.pcap"
    
    start_time = time.time()
    
    # 1. Проверка файла через VirusTotal
    vt = VirusTotalAPI()
    vt_result = vt.check_file(file_to_check)
    
    # 2. Анализ pcap файла
    pcap = PcapAnalyzer(pcap_file)
    pcap.analyze()
    
    # 3. Создание отчетов
    print(f"\n{'='*60}")
    print("СОЗДАНИЕ ОТЧЕТА")
    print(f"{'='*60}")
    
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'file_checked': {
            'path': file_to_check,
            'result': vt_result
        },
        'pcap_analysis': {
            'file': pcap_file,
            'statistics': pcap.stats,
            'threats': pcap.threats
        }
    }
    
    # Сохраняем JSON
    with open('report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("report.json создан")
    
    # Сохраняем CSV
    if pcap.threats:
        df = pd.DataFrame(pcap.threats)
        df.to_csv('report.csv', index=False, encoding='utf-8')
        print("report.csv создан")
    else:
        print("report.csv не создан (нет угроз)")
    
    # 4. Создание графиков
    create_visualizations(vt_result, pcap)
    
    elapsed = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"РАБОТА ЗАВЕРШЕНА")
    print(f"Общее время: {elapsed:.1f} сек")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()