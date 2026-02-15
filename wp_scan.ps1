<#
.SYNOPSIS
    WordPress Malware Scanner v1.1 (PowerShell 5.1 compatible)
.DESCRIPTION
    Scans a WordPress directory for malware, backdoors, web shells
    and suspicious files. Works offline, no dependencies required.
.EXAMPLE
    .\wp_scan.ps1 "C:\OpenServer\domains\mysite"
    .\wp_scan.ps1 "D:\backup\wordpress"
#>
param(
    [Parameter(Position=0)]
    [string]$ScanPath
)

# ============================================================
# SETTINGS
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
# MALWARE SIGNATURES
# ============================================================
$CriticalPatterns = @(
    @{ Pattern='eval\s*\(\s*base64_decode\s*\(';         Desc='eval(base64_decode()) - encoded code execution' }
    @{ Pattern='eval\s*\(\s*gzinflate\s*\(';              Desc='eval(gzinflate()) - compressed code execution' }
    @{ Pattern='eval\s*\(\s*gzuncompress\s*\(';            Desc='eval(gzuncompress()) - compressed code execution' }
    @{ Pattern='eval\s*\(\s*str_rot13\s*\(';               Desc='eval(str_rot13()) - obfuscated code execution' }
    @{ Pattern='eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'; Desc='eval() with user input - backdoor' }
    @{ Pattern='assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'; Desc='assert() with user input - backdoor' }
    @{ Pattern='preg_replace\s*\(.*/e\s*,';                Desc='preg_replace with /e modifier - code execution' }
    @{ Pattern='create_function\s*\(.*\$_(GET|POST|REQUEST)'; Desc='create_function with user input' }
    @{ Pattern='\$\w+\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[.+?\]\s*;\s*@?\$\w+\s*\('; Desc='Function call from user input - web shell' }
    @{ Pattern='chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)\s*\.\s*chr\(\d+\)'; Desc='String building via chr() - obfuscation' }
    @{ Pattern='\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}'; Desc='Hex-encoded string - obfuscation' }
    @{ Pattern='(FilesMan|WSO|c99|r57|b374k|Mini Shell|Web Shell)'; Desc='Known web shell signature' }
    @{ Pattern='@?ini_set\s*\(\s*.disable_functions'; Desc='Disabling PHP security functions' }
    @{ Pattern='@?ini_set\s*\(\s*.open_basedir'; Desc='Disabling open_basedir restriction' }
)

$HighPatterns = @(
    @{ Pattern='eval\s*\(\s*\$';                  Desc='eval() with variable - possible backdoor' }
    @{ Pattern='assert\s*\(\s*\$';                Desc='assert() with variable - possible backdoor' }
    @{ Pattern='shell_exec\s*\(';                 Desc='shell_exec() - system command execution' }
    @{ Pattern='system\s*\(\s*\$';                Desc='system() with variable - command execution' }
    @{ Pattern='passthru\s*\(';                   Desc='passthru() - system command execution' }
    @{ Pattern='exec\s*\(\s*\$';                  Desc='exec() with variable - command execution' }
    @{ Pattern='popen\s*\(\s*\$';                 Desc='popen() with variable' }
    @{ Pattern='proc_open\s*\(';                  Desc='proc_open() - process execution' }
    @{ Pattern='pcntl_exec\s*\(';                 Desc='pcntl_exec() - process execution' }
    @{ Pattern='base64_decode\s*\(\s*.[A-Za-z0-9+/=]{100,}'; Desc='Long base64 string - possible hidden code' }
    @{ Pattern='\$\w+\(\$\w+\)';                  Desc='Variable function call - possible obfuscation' }
    @{ Pattern='file_get_contents\s*\(\s*.(https?://|ftp://)'; Desc='Downloading from external URL' }
    @{ Pattern='file_put_contents\s*\(.+?(https?://|base64_decode|gzinflate)'; Desc='Writing downloaded/decoded content' }
    @{ Pattern='curl_exec\s*\(';                  Desc='cURL request - possible C2 communication' }
    @{ Pattern='fsockopen\s*\(';                  Desc='Socket connection - possible C2 communication' }
    @{ Pattern='move_uploaded_file\s*\(.+?\$_(GET|POST|REQUEST)'; Desc='File upload controlled by request' }
    @{ Pattern='mail\s*\(\s*\$_(GET|POST|REQUEST)'; Desc='Sending mail with request data - spam' }
)

$MediumPatterns = @(
    @{ Pattern='eval\s*\(';                       Desc='eval() - string code execution' }
    @{ Pattern='base64_decode\s*\(';              Desc='base64_decode() - decoding (may be legit)' }
    @{ Pattern='gzinflate\s*\(';                  Desc='gzinflate() - data decompression' }
    @{ Pattern='str_rot13\s*\(';                  Desc='str_rot13() - obfuscation' }
    @{ Pattern='rawurldecode\s*\(\s*.(%[0-9a-fA-F]{2}){10,}'; Desc='URL-encoded string - possible obfuscation' }
    @{ Pattern='@include\s*\(';                   Desc='@include - hidden file inclusion' }
    @{ Pattern='@require\s*\(';                   Desc='@require - hidden file inclusion' }
    @{ Pattern='error_reporting\s*\(\s*0\s*\)';   Desc='Disabling error reporting' }
    @{ Pattern='display_errors.*Off';             Desc='Hiding errors' }
    @{ Pattern='RewriteRule.*\[R=30[12]\]';       Desc='.htaccess redirect - possibly malicious' }
    @{ Pattern='document\.write\s*\(\s*unescape'; Desc='document.write(unescape()) - suspicious JS' }
    @{ Pattern='String\.fromCharCode\s*\([\d,\s]{20,}\)'; Desc='JS obfuscation via fromCharCode' }
)

$HtaccessPatterns = @(
    @{ Pattern='RewriteRule\s+.*https?://';                              Desc='Redirect to external site' }
    @{ Pattern='RewriteCond.*HTTP_REFERER.*(google|yandex|bing|facebook)'; Desc='Conditional redirect by referer (cloaking)' }
    @{ Pattern='RewriteCond.*HTTP_USER_AGENT.*(bot|crawl|spider)';        Desc='Conditional redirect by User-Agent (cloaking)' }
    @{ Pattern='php_value\s+auto_prepend_file';                          Desc='auto_prepend_file - PHP auto-include' }
    @{ Pattern='php_value\s+auto_append_file';                           Desc='auto_append_file - PHP auto-include' }
    @{ Pattern='SetHandler\s+application/x-httpd-php';                   Desc='Forced PHP handler' }
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
# RESULT VARIABLES
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
# FUNCTIONS
# ============================================================
function Add-Finding {
    param(
        [string]$FilePath,
        [int]$LineNum,
        [string]$Severity,
        [string]$Description,
        [string]$MatchedText = ""
    )
    if ($MatchedText.Length -gt 200) {
        $MatchedText = $MatchedText.Substring(0,200)
    }
    $null = $script:Findings.Add([PSCustomObject]@{
        FilePath    = $FilePath
        LineNum     = $LineNum
        Severity    = $Severity
        Description = $Description
        MatchedText = $MatchedText
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
    Write-Color "    WordPress Malware Scanner v1.1 (PowerShell)" Cyan
    Write-Color "  =============================================" Cyan
    Write-Host ""
    Write-Host "  Scan path: $ScanPath"
    Write-Host "  Started:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
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
            # Skip inaccessible directories
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
            # Skip regex errors
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
            Write-Host "`r    Scanned: $i/$total" -NoNewline
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

            # Check very long lines (obfuscation)
            if ($line.Length -gt 5000 -and $line -match '[a-zA-Z0-9+/=]{500,}') {
                Add-Finding -FilePath $relPath -LineNum $lineNum -Severity 'HIGH' `
                    -Description "Very long line ($($line.Length) chars) - possible obfuscation" `
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
                    -Description "Executable file ($ext) in uploads - likely backdoor"
                $count++
            }
        }
    }
    Write-Host "    Suspicious files in uploads: $count"
}

function Invoke-RootFilesScan {
    $count = 0
    Get-ChildItem -Path $ScanPath -File -Filter "*.php" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name.ToLower() -notin $LegitRootFiles) {
            Add-Finding -FilePath $_.Name -LineNum 0 -Severity 'HIGH' `
                -Description "Non-standard PHP file in WP root: $($_.Name)"
            $count++
        }
    }
    Write-Host "    Non-standard PHP files in root: $count"
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
    Write-Host "    Suspicious .htaccess rules: $count"
}

function Invoke-SuspiciousNamesScan {
    $count = 0
    Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name
        foreach ($pattern in $SuspiciousNamePatterns) {
            if ($name -match $pattern) {
                $relPath = $_.FullName.Substring($ScanPath.Length + 1)
                Add-Finding -FilePath $relPath -LineNum 0 -Severity 'HIGH' `
                    -Description "Suspicious filename: $name"
                $count++
                break
            }
        }
    }
    Write-Host "    Files with suspicious names: $count"
}

function Show-Results {
    Write-Host ""
    Write-Color "  ========================================" White
    Write-Color "    SCAN RESULTS" White
    Write-Color "  ========================================" White
    Write-Host ""
    Write-Host "  Files scanned: $($script:Stats.FilesScanned) of $($script:Stats.FilesTotal)"
    Write-Host ""

    $crit = $script:Stats.Critical
    $high = $script:Stats.High
    $med  = $script:Stats.Medium

    if ($crit -gt 0) { $critColor = 'Red' } else { $critColor = 'Green' }
    if ($high -gt 0) { $highColor = 'Red' } else { $highColor = 'Green' }
    if ($med -gt 0)  { $medColor = 'Yellow' } else { $medColor = 'Green' }

    Write-Color "  CRITICAL: $crit" $critColor
    Write-Color "  HIGH:     $high" $highColor
    Write-Color "  MEDIUM:   $med"  $medColor
    Write-Host ""

    if ($script:Findings.Count -eq 0) {
        Write-Color "  [OK] No suspicious code found!" Green
        Write-Host ""
        return
    }

    $byFile = $script:Findings | Group-Object -Property FilePath
    $severityOrder = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'INFO'=3 }

    $sortedGroups = $byFile | Sort-Object {
        ($_.Group | ForEach-Object { $severityOrder[$_.Severity] } | Measure-Object -Minimum).Minimum
    }

    Write-Color "  ----------------------------------------" White

    foreach ($group in $sortedGroups) {
        $sortedFindings = $group.Group | Sort-Object { $severityOrder[$_.Severity] }
        $maxSeverity = $sortedFindings[0].Severity

        switch ($maxSeverity) {
            'CRITICAL' { $fileColor = 'Red' }
            'HIGH'     { $fileColor = 'Yellow' }
            default    { $fileColor = 'White' }
        }

        Write-Host ""
        Write-Color "  [$maxSeverity] $($group.Name)" $fileColor

        $seen = @{}
        foreach ($finding in $sortedFindings) {
            $key = "$($finding.Description)|$($finding.LineNum)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            switch ($finding.Severity) {
                'CRITICAL' { $sevColor = 'Red' }
                'HIGH'     { $sevColor = 'Yellow' }
                default    { $sevColor = 'White' }
            }

            $lineInfo = ""
            if ($finding.LineNum -gt 0) { $lineInfo = " (line $($finding.LineNum))" }

            Write-Host "    " -NoNewline
            Write-Host "$($finding.Severity)" -ForegroundColor $sevColor -NoNewline
            Write-Host "${lineInfo}: $($finding.Description)"

            if ($finding.MatchedText) {
                $snippet = $finding.MatchedText
                if ($snippet.Length -gt 150) {
                    $snippet = $snippet.Substring(0,150) + "..."
                }
                Write-Host "      > $snippet" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
    Write-Color "  ----------------------------------------" White
    Write-Host ""

    if ($crit -gt 0) {
        Write-Color "  [!!!] CRITICAL THREATS DETECTED!" Red
        Write-Color "  Immediate review and cleanup recommended." Red
    } elseif ($high -gt 0) {
        Write-Color "  [!] Suspicious files detected." Yellow
        Write-Color "  Manual review recommended." Yellow
    } else {
        Write-Color "  [~] Minor suspicions found." White
        Write-Color "  Likely false positives, but worth checking." White
    }
    Write-Host ""
}

function Save-Report {
    $reportName = "wp_scan_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $reportPath = Join-Path $ScanPath $reportName

    try {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.AppendLine("WordPress Malware Scanner - Report")
        $null = $sb.AppendLine("Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $null = $sb.AppendLine("Path: $ScanPath")
        $null = $sb.AppendLine("Files scanned: $($script:Stats.FilesScanned)")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("CRITICAL: $($script:Stats.Critical)")
        $null = $sb.AppendLine("HIGH: $($script:Stats.High)")
        $null = $sb.AppendLine("MEDIUM: $($script:Stats.Medium)")
        $null = $sb.AppendLine("=" * 60)
        $null = $sb.AppendLine("")

        if ($script:Findings.Count -eq 0) {
            $null = $sb.AppendLine("No suspicious code found.")
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
                    $lineInfo = ""
                    if ($finding.LineNum -gt 0) { $lineInfo = " (line $($finding.LineNum))" }
                    $null = $sb.AppendLine("  [$($finding.Severity)]${lineInfo}: $($finding.Description)")
                    if ($finding.MatchedText) {
                        $text = $finding.MatchedText
                        if ($text.Length -gt 200) { $text = $text.Substring(0,200) }
                        $null = $sb.AppendLine("    > $text")
                    }
                }
            }
        }

        [System.IO.File]::WriteAllText($reportPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
        Write-Color "  Report saved: $reportPath" Green
    } catch {
        $altPath = Join-Path $env:USERPROFILE $reportName
        try {
            [System.IO.File]::WriteAllText($altPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
            Write-Color "  Report saved: $altPath" Yellow
        } catch {
            Write-Color "  Failed to save report: $_" Red
        }
    }
    Write-Host ""
}

# ============================================================
# MAIN
# ============================================================

if (-not $ScanPath) {
    Write-Host ""
    Write-Host "  WordPress Malware Scanner v1.1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Usage:"
    Write-Host '    .\wp_scan.ps1 "C:\path\to\site"'
    Write-Host ""
    Write-Host "  Examples:"
    Write-Host '    .\wp_scan.ps1 "C:\OpenServer\domains\mysite"'
    Write-Host '    .\wp_scan.ps1 "D:\backup\wordpress"'
    Write-Host ""
    $ScanPath = Read-Host "  Enter path to site folder"
    if (-not $ScanPath) {
        Write-Host "  No path specified. Exiting." -ForegroundColor Red
        exit 1
    }
}

$ScanPath = $ScanPath.Trim('"').Trim("'")
$ScanPath = (Resolve-Path $ScanPath -ErrorAction SilentlyContinue).Path

if (-not $ScanPath -or -not (Test-Path $ScanPath -PathType Container)) {
    Write-Color "  [ERROR] Folder not found: $ScanPath" Red
    exit 1
}

Show-Banner

Write-Color "[*] Check 1/5: Collecting files and scanning for malware signatures..." Cyan
$filesToScan = Get-FilesToScan -Path $ScanPath
$script:Stats.FilesTotal = $filesToScan.Count
Write-Host "    Files to scan: $($filesToScan.Count)"
Invoke-SignatureScan -Files $filesToScan

Write-Color "[*] Check 2/5: PHP files in uploads..." Cyan
Invoke-UploadsScan

Write-Color "[*] Check 3/5: Suspicious files in root..." Cyan
Invoke-RootFilesScan

Write-Color "[*] Check 4/5: Checking .htaccess..." Cyan
Invoke-HtaccessScan

Write-Color "[*] Check 5/5: Suspicious filenames..." Cyan
Invoke-SuspiciousNamesScan

Show-Results
Save-Report

Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray
$null = Read-Host
