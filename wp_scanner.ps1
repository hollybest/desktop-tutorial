<#
.SYNOPSIS
    WordPress Malware Scanner v1.0 (PowerShell)
    Сканер вредоносного кода для WordPress сайтов.

.DESCRIPTION
    Сканирует папку с WordPress на наличие вредоносного кода,
    бэкдоров, веб-шеллов и подозрительных файлов.

.EXAMPLE
    .\wp_scanner.ps1 "C:\OpenServer\domains\mysite"
    .\wp_scanner.ps1 "D:\backup\wordpress"

.NOTES
    Не требует установки дополнительного ПО.
    Работает полностью локально без интернета.
#>

param(
    [Parameter(Position=0)]
    [string]$ScanPath
)

# ============================================================
# НАСТРОЙКИ
# ============================================================

$ScanExtensions = @('.php','.php3','.php4','.php5','.php7','.phtml','.pht',
                     '.js','.htaccess','.html','.htm','.ico','.shtml')

$DangerousInUploads = @('.php','.php3','.php4','.php5','.php7','.phtml','.pht',
                         '.js','.exe','.sh','.bat')

$LegitRootFiles = @(
    'index.php','wp-activate.php','wp-blog-header.php',
    'wp-comments-post.php','wp-config.php','wp-config-sample.php',
    'wp-cron.php','wp-links-opml.php','wp-load.php',
    'wp-login.php','wp-mail.php','wp-settings.php',
    'wp-signup.php','wp-trackback.php','xmlrpc.php',
    'wp-config-local.php','wp-config-production.php'
)

$SkipDirs = @('.git','node_modules','__pycache__','.svn')

# ============================================================
# СИГНАТУРЫ ВРЕДОНОСНОГО КОДА
# ============================================================

$CriticalPatterns = @(
    @{ Pattern='eval\s*\(\s*base64_decode\s*\(';         Desc='eval(base64_decode()) — выполнение закодированного кода' }
    @{ Pattern='eval\s*\(\s*gzinflate\s*\(';              Desc='eval(gzinflate()) — выполнение сжатого кода' }
    @{ Pattern='eval\s*\(\s*gzuncompress\s*\(';            Desc='eval(gzuncompress()) — выполнение сжатого кода' }
    @{ Pattern='eval\s*\(\s*str_rot13\s*\(';               Desc='eval(str_rot13()) — выполнение обфусцированного кода' }
    @{ Pattern='eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'; Desc='eval() с пользовательским вводом — бэкдор' }
    @{ Pattern='assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'; Desc='assert() с пользовательским вводом — бэкдор' }
    @{ Pattern='preg_replace\s*\(.*/e[''"]\s*,';           Desc='preg_replace с /e — выполнение кода через регулярку' }
    @{ Pattern='create_function\s*\(\s*[''\"]\s*[''\"]\s*,\s*\$_(GET|POST|REQUEST)'; Desc='create_function с пользовательским вводом' }
    @{ Pattern='\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[.+?\]\s*;\s*@?\$\w+\s*\('; Desc='Вызов функции из пользовательского ввода — веб-шелл' }
    @{ Pattern='chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)'; Desc='Построение строки через chr() — обфускация' }
    @{ Pattern='\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}'; Desc='Hex-encoded строка — обфускация' }
    @{ Pattern='(FilesMan|WSO|c99|r57|b374k|Mini Shell|Web Shell)'; Desc='Известный веб-шелл' }
    @{ Pattern='@?ini_set\s*\(\s*[''"]disable_functions[''\"]\s*,\s*[''"]\s*[''"]'; Desc='Отключение защитных функций PHP' }
    @{ Pattern='@?ini_set\s*\(\s*[''"]open_basedir[''\"]\s*,\s*[''"]\s*[''"]'; Desc='Отключение open_basedir' }
)

$HighPatterns = @(
    @{ Pattern='eval\s*\(\s*\$';                  Desc='eval() с переменной — возможный бэкдор' }
    @{ Pattern='assert\s*\(\s*\$';                Desc='assert() с переменной — возможный бэкдор' }
    @{ Pattern='shell_exec\s*\(';                 Desc='shell_exec() — выполнение системных команд' }
    @{ Pattern='system\s*\(\s*\$';                Desc='system() с переменной — выполнение команд' }
    @{ Pattern='passthru\s*\(';                   Desc='passthru() — выполнение системных команд' }
    @{ Pattern='exec\s*\(\s*\$';                  Desc='exec() с переменной — выполнение команд' }
    @{ Pattern='popen\s*\(\s*\$';                 Desc='popen() с переменной' }
    @{ Pattern='proc_open\s*\(';                  Desc='proc_open() — выполнение процессов' }
    @{ Pattern='pcntl_exec\s*\(';                 Desc='pcntl_exec() — выполнение процессов' }
    @{ Pattern='base64_decode\s*\(\s*[''"][A-Za-z0-9+/=]{100,}'; Desc='Длинная base64 строка — возможный скрытый код' }
    @{ Pattern='\$\w+\(\$\w+\)';                  Desc='Вызов функции через переменную — возможная обфускация' }
    @{ Pattern='file_get_contents\s*\(\s*[''"](https?://|ftp://)'; Desc='Загрузка файлов с внешнего URL' }
    @{ Pattern='file_put_contents\s*\(.+?(https?://|base64_decode|gzinflate)'; Desc='Запись загруженного/декодированного контента' }
    @{ Pattern='curl_exec\s*\(';                  Desc='cURL запрос — возможная связь с C2 сервером' }
    @{ Pattern='fsockopen\s*\(';                  Desc='Сокет-соединение — возможная связь с C2' }
    @{ Pattern='move_uploaded_file\s*\(.+?\$_(GET|POST|REQUEST)'; Desc='Загрузка файлов с контролем из запроса' }
    @{ Pattern='@(include|require|include_once|require_once)\s*\(\s*[''"](/tmp|\\\\)'; Desc='Подключение файлов из подозрительных путей' }
    @{ Pattern='mail\s*\(\s*\$_(GET|POST|REQUEST)'; Desc='Отправка почты с данными из запроса — спам' }
)

$MediumPatterns = @(
    @{ Pattern='eval\s*\(';                       Desc='eval() — выполнение строки как кода' }
    @{ Pattern='base64_decode\s*\(';              Desc='base64_decode() — декодирование (может быть легитимным)' }
    @{ Pattern='gzinflate\s*\(';                  Desc='gzinflate() — распаковка данных' }
    @{ Pattern='str_rot13\s*\(';                  Desc='str_rot13() — обфускация' }
    @{ Pattern='rawurldecode\s*\(\s*[''"](%[0-9a-fA-F]{2}){10,}'; Desc='URL-encoded строка — возможная обфускация' }
    @{ Pattern='@include\s*\(';                   Desc='@include — скрытое подключение файлов' }
    @{ Pattern='@require\s*\(';                   Desc='@require — скрытое подключение файлов' }
    @{ Pattern='error_reporting\s*\(\s*0\s*\)';   Desc='Отключение отчётов об ошибках' }
    @{ Pattern='display_errors.*Off';             Desc='Скрытие ошибок' }
    @{ Pattern='RewriteRule.*\[R=30[12]\]';       Desc='.htaccess редирект — возможный вредоносный' }
    @{ Pattern='<\s*iframe\s+[^>]*style\s*=\s*[''"][^"]*display\s*:\s*none'; Desc='Скрытый iframe' }
    @{ Pattern='document\.write\s*\(\s*unescape'; Desc='document.write(unescape()) — подозрительный JS' }
    @{ Pattern='String\.fromCharCode\s*\([\d,\s]{20,}\)'; Desc='JS обфускация через fromCharCode' }
)

$HtaccessPatterns = @(
    @{ Pattern='RewriteRule\s+.*https?://';                              Desc='Редирект на внешний сайт' }
    @{ Pattern='RewriteCond.*HTTP_REFERER.*(google|yandex|bing|facebook)'; Desc='Условный редирект по рефереру (клоакинг)' }
    @{ Pattern='RewriteCond.*HTTP_USER_AGENT.*(bot|crawl|spider)';        Desc='Условный редирект по User-Agent (клоакинг)' }
    @{ Pattern='php_value\s+auto_prepend_file';                          Desc='auto_prepend_file — автоподключение PHP' }
    @{ Pattern='php_value\s+auto_append_file';                           Desc='auto_append_file — автоподключение PHP' }
    @{ Pattern='SetHandler\s+application/x-httpd-php';                   Desc='Принудительный PHP handler' }
    @{ Pattern='AddType\s+application/x-httpd-php\s+\.(?!php)';         Desc='PHP handler для не-PHP расширений' }
)

$SuspiciousNamePatterns = @(
    '^(shell|sh3ll|c99|r57|wso|b374k|mini|alfa|angel)\.php'
    '^(cmd|command|hack|exploit|backdoor|back|bd)\.php'
    '^(upload|uploader|up|file_upload|fileupload)\.php'
    '^(config|conf|cfg)\d+\.php'
    '^[a-z0-9]{32}\.php$'
    '^\.\w+\.php$'
    '^(thumb|cache|temp|tmp|session)[a-z0-9_]*\.php'
    '^\.\w+\.ico$'
    '^(about|class|error|widget|content|social|license)\.php$'
)

# ============================================================
# ПЕРЕМЕННЫЕ ДЛЯ РЕЗУЛЬТАТОВ
# ============================================================

$script:Findings = [System.Collections.ArrayList]::new()
$script:Stats = @{
    FilesScanned = 0
    FilesTotal   = 0
    Critical     = 0
    High         = 0
    Medium       = 0
}

# ============================================================
# ФУНКЦИИ
# ============================================================

function Add-Finding {
    param(
        [string]$FilePath,
        [int]$LineNum,
        [string]$Severity,
        [string]$Description,
        [string]$MatchedText = ""
    )
    $null = $script:Findings.Add([PSCustomObject]@{
        FilePath    = $FilePath
        LineNum     = $LineNum
        Severity    = $Severity
        Description = $Description
        MatchedText = $(if ($MatchedText.Length -gt 200) { $MatchedText.Substring(0,200) } else { $MatchedText })
    })
    switch ($Severity) {
        'CRITICAL' { $script:Stats.Critical++ }
        'HIGH'     { $script:Stats.High++ }
        'MEDIUM'   { $script:Stats.Medium++ }
    }
}

function Write-Color {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Text -ForegroundColor $Color
}

function Show-Banner {
    Write-Host ""
    Write-Color "  =============================================" Cyan
    Write-Color "    WordPress Malware Scanner v1.0 (PowerShell)" Cyan
    Write-Color "    Сканер вредоносного кода для WordPress" Cyan
    Write-Color "  =============================================" Cyan
    Write-Host ""
    Write-Host "  Путь сканирования: " -NoNewline
    Write-Color $ScanPath White
    Write-Host "  Время запуска:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""
}

function Get-FilesToScan {
    param([string]$Path)

    $files = [System.Collections.ArrayList]::new()
    $queue = [System.Collections.Queue]::new()
    $queue.Enqueue($Path)

    while ($queue.Count -gt 0) {
        $currentDir = $queue.Dequeue()
        try {
            foreach ($dir in [System.IO.Directory]::GetDirectories($currentDir)) {
                $dirName = [System.IO.Path]::GetFileName($dir)
                if ($dirName -notin $SkipDirs) {
                    $queue.Enqueue($dir)
                }
            }
            foreach ($file in [System.IO.Directory]::GetFiles($currentDir)) {
                $ext = [System.IO.Path]::GetExtension($file).ToLower()
                $name = [System.IO.Path]::GetFileName($file)
                if ($ext -in $ScanExtensions -or $name -eq '.htaccess') {
                    $null = $files.Add($file)
                }
            }
        } catch {
            # Пропускаем недоступные папки
        }
    }
    return $files
}

function Test-Patterns {
    param(
        [string]$Line,
        [array]$Patterns,
        [string]$Severity,
        [string]$RelPath,
        [int]$LineNum
    )
    foreach ($p in $Patterns) {
        try {
            if ($Line -match $p.Pattern) {
                Add-Finding -FilePath $RelPath -LineNum $LineNum -Severity $Severity `
                            -Description $p.Desc -MatchedText $Line.Trim()
            }
        } catch {
            # Пропускаем ошибки в регулярках
        }
    }
}

function Invoke-SignatureScan {
    param([array]$Files)

    $total = $Files.Count
    $i = 0

    foreach ($filePath in $Files) {
        $i++
        if ($i % 50 -eq 0 -or $i -eq $total) {
            Write-Host "`r    Проверено: $i/$total" -NoNewline
        }

        try {
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
        } catch {
            try {
                $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::GetEncoding(1251))
            } catch {
                continue
            }
        }

        $script:Stats.FilesScanned++
        $relPath = $filePath.Substring($ScanPath.Length + 1)
        $lines = $content -split "`n"

        for ($ln = 0; $ln -lt $lines.Count; $ln++) {
            $line = $lines[$ln]
            $lineNum = $ln + 1

            Test-Patterns -Line $line -Patterns $CriticalPatterns -Severity 'CRITICAL' -RelPath $relPath -LineNum $lineNum
            Test-Patterns -Line $line -Patterns $HighPatterns -Severity 'HIGH' -RelPath $relPath -LineNum $lineNum
            Test-Patterns -Line $line -Patterns $MediumPatterns -Severity 'MEDIUM' -RelPath $relPath -LineNum $lineNum

            # Проверка очень длинных строк (обфускация)
            if ($line.Length -gt 5000 -and $line -match '[a-zA-Z0-9+/=]{500,}') {
                Add-Finding -FilePath $relPath -LineNum $lineNum -Severity 'HIGH' `
                    -Description "Очень длинная строка ($($line.Length) символов) — возможная обфускация" `
                    -MatchedText $line.Substring(0, [Math]::Min(200, $line.Length))
            }
        }
    }
    Write-Host ""
}

function Invoke-UploadsScan {
    $uploadsPaths = @(
        (Join-Path $ScanPath "wp-content\uploads"),
        (Join-Path $ScanPath "uploads")
    )

    $count = 0
    foreach ($uploadsDir in $uploadsPaths) {
        if (-not (Test-Path $uploadsDir)) { continue }
        Get-ChildItem -Path $uploadsDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $ext = $_.Extension.ToLower()
            if ($ext -in $DangerousInUploads) {
                $relPath = $_.FullName.Substring($ScanPath.Length + 1)
                Add-Finding -FilePath $relPath -LineNum 0 -Severity 'CRITICAL' `
                    -Description "Исполняемый файл ($ext) в папке uploads — вероятный бэкдор"
                $count++
            }
        }
    }
    Write-Host "    Найдено подозрительных файлов в uploads: $count"
}

function Invoke-RootFilesScan {
    $count = 0
    Get-ChildItem -Path $ScanPath -File -Filter "*.php" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name.ToLower() -notin $LegitRootFiles) {
            $relPath = $_.Name
            Add-Finding -FilePath $relPath -LineNum 0 -Severity 'HIGH' `
                -Description "Нестандартный PHP файл в корне WordPress: $($_.Name)"
            $count++
        }
    }
    Write-Host "    Нестандартных PHP файлов в корне: $count"
}

function Invoke-HtaccessScan {
    $count = 0
    Get-ChildItem -Path $ScanPath -Recurse -Filter ".htaccess" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw -ErrorAction Stop
            $relPath = $_.FullName.Substring($ScanPath.Length + 1)
            $lines = $content -split "`n"

            for ($ln = 0; $ln -lt $lines.Count; $ln++) {
                $line = $lines[$ln]
                $lineNum = $ln + 1
                foreach ($p in $HtaccessPatterns) {
                    if ($line -match $p.Pattern) {
                        Add-Finding -FilePath $relPath -LineNum $lineNum -Severity 'HIGH' `
                            -Description $p.Desc -MatchedText $line.Trim()
                        $count++
                    }
                }
            }
        } catch { }
    }
    Write-Host "    Подозрительных правил в .htaccess: $count"
}

function Invoke-SuspiciousNamesScan {
    $count = 0
    Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name
        foreach ($pattern in $SuspiciousNamePatterns) {
            if ($name -match $pattern) {
                $relPath = $_.FullName.Substring($ScanPath.Length + 1)
                Add-Finding -FilePath $relPath -LineNum 0 -Severity 'HIGH' `
                    -Description "Подозрительное имя файла: $name"
                $count++
                break
            }
        }
    }
    Write-Host "    Файлов с подозрительными именами: $count"
}

function Show-Results {
    Write-Host ""
    Write-Color "  ========================================" White
    Write-Color "    РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ" White
    Write-Color "  ========================================" White
    Write-Host ""
    Write-Host "  Файлов проверено: $($script:Stats.FilesScanned) из $($script:Stats.FilesTotal)"
    Write-Host ""

    $crit = $script:Stats.Critical
    $high = $script:Stats.High
    $med  = $script:Stats.Medium

    $critColor = $(if ($crit -gt 0) { 'Red' } else { 'Green' })
    $highColor = $(if ($high -gt 0) { 'Red' } else { 'Green' })
    $medColor  = $(if ($med -gt 0) { 'Yellow' } else { 'Green' })

    Write-Color "  CRITICAL: $crit" $critColor
    Write-Color "  HIGH:     $high" $highColor
    Write-Color "  MEDIUM:   $med"  $medColor
    Write-Host ""

    if ($script:Findings.Count -eq 0) {
        Write-Color "  [OK] Подозрительный код не обнаружен!" Green
        Write-Host ""
        return
    }

    # Группируем по файлам
    $byFile = $script:Findings | Group-Object -Property FilePath

    $severityOrder = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'INFO'=3 }

    $sortedGroups = $byFile | Sort-Object {
        ($_.Group | ForEach-Object { $severityOrder[$_.Severity] } | Measure-Object -Minimum).Minimum
    }

    Write-Color "  ----------------------------------------" White

    foreach ($group in $sortedGroups) {
        $sortedFindings = $group.Group | Sort-Object { $severityOrder[$_.Severity] }
        $maxSeverity = $sortedFindings[0].Severity

        $fileColor = switch ($maxSeverity) {
            'CRITICAL' { 'Red' }
            'HIGH'     { 'Yellow' }
            default    { 'White' }
        }

        Write-Host ""
        Write-Color "  [$maxSeverity] $($group.Name)" $fileColor

        $seen = @{}
        foreach ($finding in $sortedFindings) {
            $key = "$($finding.Description)|$($finding.LineNum)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $sevColor = switch ($finding.Severity) {
                'CRITICAL' { 'Red' }
                'HIGH'     { 'Yellow' }
                default    { 'White' }
            }

            $lineInfo = $(if ($finding.LineNum -gt 0) { " (строка $($finding.LineNum))" } else { "" })
            Write-Host "    " -NoNewline
            Write-Host "$($finding.Severity)" -ForegroundColor $sevColor -NoNewline
            Write-Host "${lineInfo}: $($finding.Description)"

            if ($finding.MatchedText) {
                $snippet = $(if ($finding.MatchedText.Length -gt 150) {
                    $finding.MatchedText.Substring(0,150) + "..."
                } else {
                    $finding.MatchedText
                })
                Write-Host "      > $snippet" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
    Write-Color "  ----------------------------------------" White
    Write-Host ""

    if ($crit -gt 0) {
        Write-Color "  [!!!] ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ УГРОЗЫ!" Red
        Write-Color "  Рекомендуется немедленная проверка и очистка." Red
    } elseif ($high -gt 0) {
        Write-Color "  [!] Обнаружены подозрительные файлы." Yellow
        Write-Color "  Рекомендуется проверить вручную." Yellow
    } else {
        Write-Color "  [~] Обнаружены незначительные подозрения." White
        Write-Color "  Скорее всего ложные срабатывания, но стоит проверить." White
    }
    Write-Host ""
}

function Save-Report {
    $reportName = "wp_scan_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $reportPath = Join-Path $ScanPath $reportName

    try {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.AppendLine("WordPress Malware Scanner - Отчёт")
        $null = $sb.AppendLine("Дата: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $null = $sb.AppendLine("Путь: $ScanPath")
        $null = $sb.AppendLine("Файлов проверено: $($script:Stats.FilesScanned)")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("CRITICAL: $($script:Stats.Critical)")
        $null = $sb.AppendLine("HIGH: $($script:Stats.High)")
        $null = $sb.AppendLine("MEDIUM: $($script:Stats.Medium)")
        $null = $sb.AppendLine("=" * 60)
        $null = $sb.AppendLine("")

        if ($script:Findings.Count -eq 0) {
            $null = $sb.AppendLine("Подозрительный код не обнаружен.")
        } else {
            $byFile = $script:Findings | Group-Object -Property FilePath | Sort-Object Name
            foreach ($group in $byFile) {
                $null = $sb.AppendLine("")
                $null = $sb.AppendLine("--- $($group.Name) ---")
                $seen = @{}
                foreach ($finding in $group.Group) {
                    $key = "$($finding.Description)|$($finding.LineNum)"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $lineInfo = $(if ($finding.LineNum -gt 0) { " (строка $($finding.LineNum))" } else { "" })
                    $null = $sb.AppendLine("  [$($finding.Severity)]${lineInfo}: $($finding.Description)")
                    if ($finding.MatchedText) {
                        $text = $(if ($finding.MatchedText.Length -gt 200) { $finding.MatchedText.Substring(0,200) } else { $finding.MatchedText })
                        $null = $sb.AppendLine("    > $text")
                    }
                }
            }
        }

        [System.IO.File]::WriteAllText($reportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
        Write-Color "  Отчёт сохранён: $reportPath" Green
    } catch {
        $altPath = Join-Path $env:USERPROFILE $reportName
        try {
            [System.IO.File]::WriteAllText($altPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
            Write-Color "  Отчёт сохранён: $altPath" Yellow
        } catch {
            Write-Color "  Не удалось сохранить отчёт: $_" Red
        }
    }
    Write-Host ""
}

# ============================================================
# ЗАПУСК
# ============================================================

# Если путь не передан — спрашиваем
if (-not $ScanPath) {
    Write-Host ""
    Write-Host "  WordPress Malware Scanner v1.0" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Использование:"
    Write-Host '    .\wp_scanner.ps1 "C:\путь\к\сайту"'
    Write-Host ""
    Write-Host "  Примеры:"
    Write-Host '    .\wp_scanner.ps1 "C:\OpenServer\domains\mysite"'
    Write-Host '    .\wp_scanner.ps1 "D:\backup\wordpress"'
    Write-Host ""
    $ScanPath = Read-Host "  Введите путь к папке с сайтом"
    if (-not $ScanPath) {
        Write-Host "  Путь не указан. Выход." -ForegroundColor Red
        exit 1
    }
}

# Убираем кавычки если есть
$ScanPath = $ScanPath.Trim('"').Trim("'")
$ScanPath = (Resolve-Path $ScanPath -ErrorAction SilentlyContinue).Path

if (-not $ScanPath -or -not (Test-Path $ScanPath -PathType Container)) {
    Write-Color "  [ОШИБКА] Папка не найдена: $ScanPath" Red
    exit 1
}

# Запуск
Show-Banner

Write-Color "[*] Проверка 1/5: Собираю файлы и ищу вредоносные сигнатуры..." Cyan
$filesToScan = Get-FilesToScan -Path $ScanPath
$script:Stats.FilesTotal = $filesToScan.Count
Write-Host "    Найдено файлов для проверки: $($filesToScan.Count)"
Invoke-SignatureScan -Files $filesToScan

Write-Color "[*] Проверка 2/5: PHP файлы в uploads..." Cyan
Invoke-UploadsScan

Write-Color "[*] Проверка 3/5: Подозрительные файлы в корне..." Cyan
Invoke-RootFilesScan

Write-Color "[*] Проверка 4/5: Проверка .htaccess..." Cyan
Invoke-HtaccessScan

Write-Color "[*] Проверка 5/5: Подозрительные имена файлов..." Cyan
Invoke-SuspiciousNamesScan

Show-Results
Save-Report

Write-Host "  Нажмите Enter для выхода..." -ForegroundColor DarkGray
$null = Read-Host
