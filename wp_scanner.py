#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WordPress Malware Scanner v1.0
Сканер вредоносного кода для WordPress сайтов.

Использование:
    python wp_scanner.py "C:\путь\к\сайту"
    python wp_scanner.py /var/www/html/mysite

Автор: Claude Code
"""

import os
import sys
import re
import hashlib
import datetime
import json
from pathlib import Path
from collections import defaultdict

# ============================================================
# НАСТРОЙКИ
# ============================================================

# Расширения файлов для проверки
SCAN_EXTENSIONS = {
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.pht',
    '.js', '.htaccess', '.html', '.htm', '.ico', '.shtml'
}

# Файлы которые НЕ должны быть в uploads
DANGEROUS_IN_UPLOADS = {'.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.pht', '.js', '.exe', '.sh', '.bat'}

# ============================================================
# СИГНАТУРЫ ВРЕДОНОСНОГО КОДА
# ============================================================

# Критические — почти наверняка малварь
CRITICAL_PATTERNS = [
    (r'eval\s*\(\s*base64_decode\s*\(', 'eval(base64_decode()) — выполнение закодированного кода'),
    (r'eval\s*\(\s*gzinflate\s*\(', 'eval(gzinflate()) — выполнение сжатого кода'),
    (r'eval\s*\(\s*gzuncompress\s*\(', 'eval(gzuncompress()) — выполнение сжатого кода'),
    (r'eval\s*\(\s*str_rot13\s*\(', 'eval(str_rot13()) — выполнение обфусцированного кода'),
    (r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'eval() с пользовательским вводом — бэкдор'),
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'assert() с пользовательским вводом — бэкдор'),
    (r'preg_replace\s*\(.*/e[\'"]\s*,', 'preg_replace с /e — выполнение кода через регулярку'),
    (r'create_function\s*\(\s*[\'\"]\s*[\'\"],\s*\$_(GET|POST|REQUEST)', 'create_function с пользовательским вводом'),
    (r'\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[.+?\]\s*;\s*@?\$\w+\s*\(', 'Вызов функции из пользовательского ввода — веб-шелл'),
    (r'chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)', 'Построение строки через chr() — обфускация'),
    (r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', 'Hex-encoded строка — обфускация'),
    (r'(FilesMan|WSO|c99|r57|b374k|Mini Shell|Web Shell)', 'Известный веб-шелл'),
    (r'@?ini_set\s*\(\s*[\'"]disable_functions[\'"]\s*,\s*[\'"]\s*[\'"]', 'Отключение защитных функций PHP'),
    (r'@?ini_set\s*\(\s*[\'"]open_basedir[\'"]\s*,\s*[\'"]\s*[\'"]', 'Отключение open_basedir'),
]

# Высокий риск — подозрительно, нужна проверка
HIGH_PATTERNS = [
    (r'eval\s*\(\s*\$', 'eval() с переменной — возможный бэкдор'),
    (r'assert\s*\(\s*\$', 'assert() с переменной — возможный бэкдор'),
    (r'shell_exec\s*\(', 'shell_exec() — выполнение системных команд'),
    (r'system\s*\(\s*\$', 'system() с переменной — выполнение команд'),
    (r'passthru\s*\(', 'passthru() — выполнение системных команд'),
    (r'exec\s*\(\s*\$', 'exec() с переменной — выполнение команд'),
    (r'popen\s*\(\s*\$', 'popen() с переменной'),
    (r'proc_open\s*\(', 'proc_open() — выполнение процессов'),
    (r'pcntl_exec\s*\(', 'pcntl_exec() — выполнение процессов'),
    (r'base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{100,}', 'Длинная base64 строка — возможный скрытый код'),
    (r'\$\w+\(\$\w+\)', 'Вызов функции через переменную — возможная обфускация'),
    (r'file_get_contents\s*\(\s*[\'"](https?://|ftp://)', 'Загрузка файлов с внешнего URL'),
    (r'file_put_contents\s*\(.+?(https?://|base64_decode|gzinflate)', 'Запись загруженного/декодированного контента'),
    (r'curl_exec\s*\(', 'cURL запрос — возможная связь с C2 сервером'),
    (r'fsockopen\s*\(', 'Сокет-соединение — возможная связь с C2'),
    (r'\\[\'"]\\s*\.\s*\\[\'"]\\s*\.', 'Конкатенация строк — возможная обфускация'),
    (r'move_uploaded_file\s*\(.+?\$_(GET|POST|REQUEST)', 'Загрузка файлов с контролем из запроса'),
    (r'@(include|require|include_once|require_once)\s*\(\s*[\'"](/tmp|\\\\)', 'Подключение файлов из подозрительных путей'),
    (r'mail\s*\(\s*\$_(GET|POST|REQUEST)', 'Отправка почты с данными из запроса — спам'),
]

# Средний риск — может быть легитимным, но стоит проверить
MEDIUM_PATTERNS = [
    (r'eval\s*\(', 'eval() — выполнение строки как кода'),
    (r'base64_decode\s*\(', 'base64_decode() — декодирование (может быть легитимным)'),
    (r'gzinflate\s*\(', 'gzinflate() — распаковка данных'),
    (r'str_rot13\s*\(', 'str_rot13() — обфускация'),
    (r'rawurldecode\s*\(\s*[\'"](%[0-9a-fA-F]{2}){10,}', 'URL-encoded строка — возможная обфускация'),
    (r'@include\s*\(', '@include — скрытое подключение файлов (подавление ошибок)'),
    (r'@require\s*\(', '@require — скрытое подключение файлов'),
    (r'error_reporting\s*\(\s*0\s*\)', 'Отключение отчётов об ошибках'),
    (r'display_errors.*Off', 'Скрытие ошибок'),
    (r'RewriteRule.*\[R=30[12]\]', '.htaccess редирект — возможный вредоносный'),
    (r'<\s*iframe\s+[^>]*style\s*=\s*[\'"][^"]*display\s*:\s*none', 'Скрытый iframe'),
    (r'<\s*script[^>]*src\s*=\s*[\'"]https?://(?!.*(?:google|facebook|jquery|cloudflare|wordpress))', 'Внешний скрипт с неизвестного домена'),
    (r'document\.write\s*\(\s*unescape', 'document.write(unescape()) — подозрительный JS'),
    (r'window\[[\'"](\\x|\\u)', 'Обфусцированный JavaScript'),
    (r'String\.fromCharCode\s*\([\d,\s]{20,}\)', 'JS обфускация через fromCharCode'),
]

# ============================================================
# КЛАССЫ
# ============================================================

class Colors:
    """ANSI цвета для терминала"""
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @staticmethod
    def supports_color():
        if os.name == 'nt':
            os.system('')  # Включаем ANSI на Windows
            return True
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


class Finding:
    """Одна находка сканера"""
    def __init__(self, file_path, line_num, severity, description, matched_text=""):
        self.file_path = file_path
        self.line_num = line_num
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, INFO
        self.description = description
        self.matched_text = matched_text[:200]  # обрезаем длинные строки


class WPScanner:
    """Основной класс сканера"""

    def __init__(self, scan_path):
        self.scan_path = Path(scan_path).resolve()
        self.findings = []
        self.stats = {
            'files_scanned': 0,
            'files_total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'info': 0,
        }
        self.use_color = Colors.supports_color()

    def colorize(self, text, color):
        if self.use_color:
            return f"{color}{text}{Colors.RESET}"
        return text

    def add_finding(self, file_path, line_num, severity, description, matched_text=""):
        finding = Finding(file_path, line_num, severity, description, matched_text)
        self.findings.append(finding)
        severity_lower = severity.lower()
        if severity_lower in self.stats:
            self.stats[severity_lower] += 1

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════╗
║           WordPress Malware Scanner v1.0                ║
║                                                         ║
║  Сканер вредоносного кода для WordPress                 ║
╚══════════════════════════════════════════════════════════╝
"""
        print(self.colorize(banner, Colors.CYAN))
        print(f"  Путь сканирования: {self.colorize(str(self.scan_path), Colors.WHITE)}")
        print(f"  Время запуска:     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

    def scan(self):
        """Главный метод сканирования"""
        self.print_banner()

        if not self.scan_path.exists():
            print(self.colorize(f"[ОШИБКА] Путь не найден: {self.scan_path}", Colors.RED))
            return

        # Собираем файлы
        print(self.colorize("[*] Собираю список файлов...", Colors.CYAN))
        files_to_scan = self._collect_files()
        self.stats['files_total'] = len(files_to_scan)
        print(f"    Найдено файлов для проверки: {len(files_to_scan)}")
        print()

        # Запускаем проверки
        print(self.colorize("[*] Проверка 1/5: Поиск вредоносных сигнатур...", Colors.CYAN))
        self._scan_signatures(files_to_scan)

        print(self.colorize("[*] Проверка 2/5: PHP файлы в uploads...", Colors.CYAN))
        self._scan_uploads()

        print(self.colorize("[*] Проверка 3/5: Подозрительные файлы в корне...", Colors.CYAN))
        self._scan_root_files()

        print(self.colorize("[*] Проверка 4/5: Проверка .htaccess...", Colors.CYAN))
        self._scan_htaccess()

        print(self.colorize("[*] Проверка 5/5: Подозрительные имена файлов...", Colors.CYAN))
        self._scan_suspicious_filenames()

        print()

        # Выводим результаты
        self._print_results()
        self._save_report()

    def _collect_files(self):
        """Собирает список файлов для сканирования"""
        files = []
        for root, dirs, filenames in os.walk(self.scan_path):
            # Пропускаем тяжёлые директории
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.svn'}]
            for fname in filenames:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                if ext in SCAN_EXTENSIONS or fname == '.htaccess':
                    files.append(fpath)
        return files

    def _scan_signatures(self, files):
        """Поиск вредоносных паттернов в файлах"""
        total = len(files)
        for i, fpath in enumerate(files):
            if (i + 1) % 100 == 0 or i == total - 1:
                print(f"\r    Проверено: {i+1}/{total}", end='', flush=True)

            try:
                content = fpath.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')
            except (PermissionError, OSError):
                continue

            self.stats['files_scanned'] += 1
            rel_path = str(fpath.relative_to(self.scan_path))

            for line_num, line in enumerate(lines, 1):
                # Критические
                for pattern, desc in CRITICAL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(rel_path, line_num, 'CRITICAL', desc, line.strip())

                # Высокий риск
                for pattern, desc in HIGH_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(rel_path, line_num, 'HIGH', desc, line.strip())

                # Средний риск
                for pattern, desc in MEDIUM_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(rel_path, line_num, 'MEDIUM', desc, line.strip())

            # Проверка на очень длинные строки (обфускация)
            for line_num, line in enumerate(lines, 1):
                if len(line) > 5000 and re.search(r'[a-zA-Z0-9+/=]{500,}', line):
                    self.add_finding(rel_path, line_num, 'HIGH',
                                   f'Очень длинная строка ({len(line)} символов) — возможная обфускация',
                                   line[:200])

        print()

    def _scan_uploads(self):
        """Проверяет наличие исполняемых файлов в uploads"""
        uploads_paths = [
            self.scan_path / 'wp-content' / 'uploads',
            self.scan_path / 'uploads',
        ]

        count = 0
        for uploads_dir in uploads_paths:
            if not uploads_dir.exists():
                continue
            for root, dirs, files in os.walk(uploads_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    ext = fpath.suffix.lower()
                    if ext in DANGEROUS_IN_UPLOADS:
                        rel_path = str(fpath.relative_to(self.scan_path))
                        self.add_finding(rel_path, 0, 'CRITICAL',
                                       f'Исполняемый файл ({ext}) в папке uploads — вероятный бэкдор')
                        count += 1

        print(f"    Найдено подозрительных файлов в uploads: {count}")

    def _scan_root_files(self):
        """Проверяет подозрительные PHP файлы в корне WordPress"""
        # Легитимные файлы WordPress в корне
        legit_root_files = {
            'index.php', 'wp-activate.php', 'wp-blog-header.php',
            'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php',
            'wp-cron.php', 'wp-links-opml.php', 'wp-load.php',
            'wp-login.php', 'wp-mail.php', 'wp-settings.php',
            'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
            'wp-config-local.php', 'wp-config-production.php',
        }

        count = 0
        for item in self.scan_path.iterdir():
            if item.is_file() and item.suffix.lower() == '.php':
                if item.name.lower() not in legit_root_files:
                    rel_path = str(item.relative_to(self.scan_path))
                    self.add_finding(rel_path, 0, 'HIGH',
                                   f'Нестандартный PHP файл в корне WordPress: {item.name}')
                    count += 1

        print(f"    Нестандартных PHP файлов в корне: {count}")

    def _scan_htaccess(self):
        """Проверяет .htaccess файлы"""
        count = 0
        for root, dirs, files in os.walk(self.scan_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules'}]
            if '.htaccess' in files:
                htaccess_path = Path(root) / '.htaccess'
                try:
                    content = htaccess_path.read_text(encoding='utf-8', errors='ignore')
                    rel_path = str(htaccess_path.relative_to(self.scan_path))

                    # Проверяем подозрительные редиректы
                    suspicious_htaccess = [
                        (r'RewriteRule\s+.*https?://(?!.*(?:www\.|%{HTTP_HOST}))', 'Редирект на внешний сайт'),
                        (r'RewriteCond.*HTTP_REFERER.*(google|yandex|bing|facebook)', 'Условный редирект по рефереру (клоакинг)'),
                        (r'RewriteCond.*HTTP_USER_AGENT.*(bot|crawl|spider)', 'Условный редирект по User-Agent (клоакинг)'),
                        (r'php_value\s+auto_prepend_file', 'auto_prepend_file — автоподключение PHP'),
                        (r'php_value\s+auto_append_file', 'auto_append_file — автоподключение PHP'),
                        (r'SetHandler\s+application/x-httpd-php', 'Принудительный PHP handler — может исполнять не-PHP файлы'),
                        (r'AddType\s+application/x-httpd-php\s+\.(?!php)', 'PHP handler для не-PHP расширений'),
                    ]

                    lines = content.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        for pattern, desc in suspicious_htaccess:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.add_finding(rel_path, line_num, 'HIGH', desc, line.strip())
                                count += 1

                except (PermissionError, OSError):
                    pass

        print(f"    Подозрительных правил в .htaccess: {count}")

    def _scan_suspicious_filenames(self):
        """Ищет файлы с подозрительными именами"""
        suspicious_names = [
            r'^(shell|sh3ll|c99|r57|wso|b374k|mini|alfa|angel)\.php',
            r'^(cmd|command|hack|exploit|backdoor|back|bd)\.php',
            r'^(upload|uploader|up|file_upload|fileupload)\.php',
            r'^(config|conf|cfg)\d+\.php',
            r'^[a-z0-9]{32}\.php$',  # MD5-хеш как имя файла
            r'^\.[\w]+\.php$',  # Скрытые PHP файлы (.something.php)
            r'^(thumb|cache|temp|tmp|session)[a-z0-9_]*\.php',
            r'^\.\w+\.ico$',  # Скрытые .ico файлы (часто бэкдоры)
            r'^(about|class|error|widget|content|social|license)\.php$',  # Маскировка
        ]

        count = 0
        for root, dirs, files in os.walk(self.scan_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules'}]
            for fname in files:
                for pattern in suspicious_names:
                    if re.match(pattern, fname, re.IGNORECASE):
                        fpath = Path(root) / fname
                        rel_path = str(fpath.relative_to(self.scan_path))
                        self.add_finding(rel_path, 0, 'HIGH',
                                       f'Подозрительное имя файла: {fname}')
                        count += 1
                        break

        print(f"    Файлов с подозрительными именами: {count}")

    def _print_results(self):
        """Выводит результаты сканирования"""
        print(self.colorize("=" * 60, Colors.WHITE))
        print(self.colorize("  РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ", Colors.BOLD))
        print(self.colorize("=" * 60, Colors.WHITE))
        print()
        print(f"  Файлов проверено: {self.stats['files_scanned']} из {self.stats['files_total']}")
        print()

        # Статистика по уровням
        crit = self.stats['critical']
        high = self.stats['high']
        med = self.stats['medium']

        print(f"  {self.colorize(f'CRITICAL: {crit}', Colors.RED if crit > 0 else Colors.GREEN)}")
        print(f"  {self.colorize(f'HIGH:     {high}', Colors.RED if high > 0 else Colors.GREEN)}")
        print(f"  {self.colorize(f'MEDIUM:   {med}', Colors.YELLOW if med > 0 else Colors.GREEN)}")
        print()

        if not self.findings:
            print(self.colorize("  [OK] Подозрительный код не обнаружен!", Colors.GREEN))
            print()
            return

        # Группируем по файлам
        by_file = defaultdict(list)
        for f in self.findings:
            by_file[f.file_path].append(f)

        # Сначала критические
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
        sorted_files = sorted(by_file.keys(),
                            key=lambda fp: min(severity_order.get(f.severity, 99) for f in by_file[fp]))

        print(self.colorize("-" * 60, Colors.WHITE))

        for file_path in sorted_files:
            file_findings = sorted(by_file[file_path],
                                 key=lambda f: severity_order.get(f.severity, 99))
            max_severity = file_findings[0].severity

            if max_severity == 'CRITICAL':
                color = Colors.RED
            elif max_severity == 'HIGH':
                color = Colors.YELLOW
            else:
                color = Colors.WHITE

            print()
            print(self.colorize(f"  [{max_severity}] {file_path}", color))

            seen = set()
            for finding in file_findings:
                key = (finding.description, finding.line_num)
                if key in seen:
                    continue
                seen.add(key)

                sev_color = Colors.RED if finding.severity == 'CRITICAL' else (
                    Colors.YELLOW if finding.severity == 'HIGH' else Colors.WHITE)

                line_info = f" (строка {finding.line_num})" if finding.line_num > 0 else ""
                print(f"    {self.colorize(finding.severity, sev_color)}{line_info}: {finding.description}")

                if finding.matched_text:
                    # Показываем фрагмент кода
                    snippet = finding.matched_text[:150]
                    if len(finding.matched_text) > 150:
                        snippet += "..."
                    print(f"      > {snippet}")

        print()
        print(self.colorize("-" * 60, Colors.WHITE))
        total = crit + high + med
        print()

        if crit > 0:
            print(self.colorize("  [!!!] ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ УГРОЗЫ!", Colors.RED))
            print(self.colorize("  Рекомендуется немедленная проверка и очистка.", Colors.RED))
        elif high > 0:
            print(self.colorize("  [!] Обнаружены подозрительные файлы.", Colors.YELLOW))
            print(self.colorize("  Рекомендуется проверить вручную.", Colors.YELLOW))
        else:
            print(self.colorize("  [~] Обнаружены незначительные подозрения.", Colors.WHITE))
            print(self.colorize("  Скорее всего ложные срабатывания, но стоит проверить.", Colors.WHITE))

        print()

    def _save_report(self):
        """Сохраняет отчёт в файл"""
        report_name = f"wp_scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = self.scan_path / report_name

        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("WordPress Malware Scanner - Отчёт\n")
                f.write(f"Дата: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Путь: {self.scan_path}\n")
                f.write(f"Файлов проверено: {self.stats['files_scanned']}\n")
                f.write(f"\nCRITICAL: {self.stats['critical']}\n")
                f.write(f"HIGH: {self.stats['high']}\n")
                f.write(f"MEDIUM: {self.stats['medium']}\n")
                f.write("=" * 60 + "\n\n")

                if not self.findings:
                    f.write("Подозрительный код не обнаружен.\n")
                else:
                    by_file = defaultdict(list)
                    for finding in self.findings:
                        by_file[finding.file_path].append(finding)

                    for file_path, file_findings in sorted(by_file.items()):
                        f.write(f"\n--- {file_path} ---\n")
                        seen = set()
                        for finding in file_findings:
                            key = (finding.description, finding.line_num)
                            if key in seen:
                                continue
                            seen.add(key)
                            line_info = f" (строка {finding.line_num})" if finding.line_num > 0 else ""
                            f.write(f"  [{finding.severity}]{line_info}: {finding.description}\n")
                            if finding.matched_text:
                                f.write(f"    > {finding.matched_text[:200]}\n")

            print(self.colorize(f"  Отчёт сохранён: {report_path}", Colors.GREEN))
            print()
        except (PermissionError, OSError) as e:
            # Пробуем сохранить в домашнюю директорию
            alt_path = Path.home() / report_name
            try:
                with open(alt_path, 'w', encoding='utf-8') as f:
                    f.write(f"Не удалось сохранить в {report_path}: {e}\n")
                print(self.colorize(f"  Отчёт сохранён: {alt_path}", Colors.YELLOW))
            except Exception:
                print(self.colorize(f"  Не удалось сохранить отчёт: {e}", Colors.RED))
            print()


# ============================================================
# ЗАПУСК
# ============================================================

def main():
    if len(sys.argv) < 2:
        print()
        print("Использование: python wp_scanner.py <путь_к_сайту>")
        print()
        print("Примеры:")
        print('  python wp_scanner.py "C:\\OpenServer\\domains\\mysite"')
        print('  python wp_scanner.py "C:\\Users\\User\\Desktop\\mysite"')
        print("  python wp_scanner.py /var/www/html/wordpress")
        print()
        sys.exit(1)

    scan_path = sys.argv[1]
    scanner = WPScanner(scan_path)
    scanner.scan()


if __name__ == '__main__':
    main()
