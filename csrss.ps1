function Check-FilePresence {
    param (
        [string]$FilePathToCheck
    )
    return (Test-Path $FilePathToCheck) -and (-not (Test-Path $FilePathToCheck -PathType Leaf))
}

function Validate-FileSignature {
    param (
        [string]$FilePathToValidate
    )
    if (-not (Test-Path $FilePathToValidate -PathType Leaf)) {
        return $false
    }

    try {
        $SignatureVerification = Get-AuthenticodeSignature -FilePath $FilePathToValidate | Where-Object { $_.Status -eq 'Valid' }
        return $SignatureVerification.Count -gt 0
    }
    catch {
        return $false
    }
}

function Execute-CSRSSScan {
    Write-Host "Scanning file txt CSRSS... Please hold on, this may take a moment." -ForegroundColor DarkMagenta

    $FilePath1 = "C:\Search results.txt"
    $FilePath2 = "C:\Search results2.txt"
    $ScanResults = @{
        "Not Signed - Executed File" = @()
        "Not Signed - DLL Injection" = @()
        "Not Present - Without Extension" = @()
        "Not Signed - Modified" = @()
    }

    $ModifiedExtensionPattern = "(?!.*(\.exe|\.dll|\\|\.dll\..*\.config|\.exe\.config)$)^[A-Z]:\\.*\..*"
    $DllInjectionPattern = "^[A-Za-z]:\\.*\.dll$"
    $ExecutedFilePattern = "^[A-Za-z]:\\.+?.exe"
    $FilesWithoutExtensionPattern1 = "^[A-Za-z]:\\(?:[^.\\]+\\)*[^.\\]+$"
    $FilesWithoutExtensionPattern2 = "^\\?\?\\?\\(?:[^.\\]+\\)*[^.\\]+$"

    $MaxLineLength = 260
    $AlreadyPrintedMatches = @()

    foreach ($CurrentFilePath in @($FilePath1, $FilePath2)) {
        if (Test-Path $CurrentFilePath) {
            if ((Test-Path $CurrentFilePath -PathType Leaf) -and (-not (Test-Path $CurrentFilePath -PathType Container))) {
                $InputFileContent = Get-Content $CurrentFilePath
                foreach ($CurrentLine in $InputFileContent) {
                    if ($CurrentLine.Length -gt $MaxLineLength) {
                        continue
                    }

                    $ColonPosition = $CurrentLine.IndexOf(':')
                    if ($ColonPosition -ne -1 -and $ColonPosition + 2 -lt $CurrentLine.Length) {
                        $MatchedString = $CurrentLine.Substring($ColonPosition + 2).Trim()

                        if ($MatchedString.EndsWith('\')) {
                            continue
                        }

                        if ($MatchedString -match $DllInjectionPattern -and -not $AlreadyPrintedMatches.Contains($MatchedString)) {
                            if ((Test-Path $MatchedString) -and (-not (Validate-FileSignature $MatchedString))) {
                                $ScanResults["Not Signed - DLL Injection"] += $MatchedString
                            }
                            $AlreadyPrintedMatches += $MatchedString
                        }
                        elseif ($MatchedString -match $ExecutedFilePattern -and -not $AlreadyPrintedMatches.Contains($MatchedString)) {
                            if ((Test-Path $MatchedString) -and (-not (Validate-FileSignature $MatchedString))) {
                                $ScanResults["Not Signed - Executed File"] += $MatchedString
                            }
                            $AlreadyPrintedMatches += $MatchedString
                        }
                        elseif ($MatchedString -match $ModifiedExtensionPattern -and -not $AlreadyPrintedMatches.Contains($MatchedString) -and -not ($MatchedString -match $DllInjectionPattern)) {
                            $FileExtension = [System.IO.Path]::GetExtension($MatchedString)
                            
                            if ($FileExtension -notin @('.exe', '.dll', '.jar')) { # You can edit extension
                                if ((Test-Path $MatchedString) -and (-not (Validate-FileSignature $MatchedString))) {
                                    $ScanResults["Not Signed - Modified (file-present)"] += $MatchedString
                                }
                                $AlreadyPrintedMatches += $MatchedString
                            }
                        }

                        if (($MatchedString -match $FilesWithoutExtensionPattern1 -or $MatchedString -match $FilesWithoutExtensionPattern2) -and -not (Test-Path $MatchedString)) {
                            $ScanResults["Not Present - Without Extension"] += $MatchedString
                        }
                    }
                }
            }
        }
        else {
            Write-Host "No .txt's detected in C:" -ForegroundColor Red
        }
    }

    return $ScanResults
}

$ScanResults = Execute-CSRSSScan

$htmlOutputPath = "C:\CSRSS.html"
if (Test-Path $htmlOutputPath) {
    Remove-Item $htmlOutputPath -Force
}
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRSS Analyzer</title>
    <style>
    body { 
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        margin: 0; 
        padding: 20px; 
        background-color: #1a1a1a;
        color: #e0e0e0;
    }
    h1 {
        text-align: center;
        color: #f0ad4e;
        margin-bottom: 20px;
        font-size: 28px;
        text-shadow: 1px 1px 2px #000;
    }
    table { 
        width: 100%; 
        border-collapse: collapse; 
        margin-top: 20px; 
        border-radius: 10px;
        overflow: hidden;
    }
    th { 
        padding: 15px; 
        text-align: left; 
        background-color: #343a40;
        color: #f8f9fa;
    }
    tr { 
        background-color: #495057;
    }
    tr:hover { 
        background-color: #6c757d;
    }
    td { 
        padding: 10px; 
        background-color: #212529;
        border: none;
    }
    td:hover { 
        background-color: #343a40;
    }
    footer {
        margin-top: 20px;
        text-align: center;
        font-size: 14px;
        color: #b0b3b7;
    }
</style>
</head>
<body>
    <h1>CSRSS Analyzer Results</h1>
    <table>
        <thead>
            <tr>
                <th>Not Signed - Executed File</th>
                <th>Not Signed - Modified (file-present)</th>
                <th>Not Present - Without Extension</th>
                <th>Not Signed - DLL Injection</th>
            </tr>
        </thead>
        <tbody>
"@

$MaximumCount = 0
foreach ($ResultKey in $ScanResults.Keys) {
    if ($ScanResults[$ResultKey].Count -gt $MaximumCount) {
        $MaximumCount = $ScanResults[$ResultKey].Count
    }
}

for ($RowIndex = 0; $RowIndex -lt $MaximumCount; $RowIndex++) {
    $RowHtml = "<tr>"
    foreach ($ResultKey in $ScanResults.Keys) {
        $CellValue = if ($RowIndex -lt $ScanResults[$ResultKey].Count) { $ScanResults[$ResultKey][$RowIndex] } else { "" }
        $RowHtml += "<td>$CellValue</td>"
    }
    $RowHtml += "</tr>"
    $htmlContent += $RowHtml
}

$htmlContent += @"
        </tbody>
    </table>
</body>
</html>
"@

$htmlContent | Out-File -Encoding utf8 -FilePath $htmlOutputPath
Start-Process $htmlOutputPath