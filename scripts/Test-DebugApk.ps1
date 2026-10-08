param(
    [string]$ApkPath,
    [string]$ApkAnalyzer = 'apkanalyzer',
    [string]$OutputPath
)

function Get-ApkDebugClassification {
    param([string]$ManifestXml)
    try {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($ManifestXml), $settings)
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        try { $doc.Load($reader) } finally { $reader.Dispose() }
        if ($doc.DocumentElement.Name -ne 'manifest') { return 'unknown' }
        $apps = $doc.SelectNodes('/manifest/application')
        if ($apps.Count -ne 1) { return 'unknown' }
        $flag = $apps[0].GetAttributeNode('debuggable', 'http://schemas.android.com/apk/res/android')
        if ($null -eq $flag) { return 'non-debug' }
        if ($flag.Value -ceq 'true') { return 'debug' }
        if ($flag.Value -ceq 'false') { return 'non-debug' }
        return 'unknown'
    } catch { return 'unknown' }
}

function Get-ApkFileSha256 {
    param([string]$LiteralPath)
    $stream = [System.IO.File]::OpenRead($LiteralPath)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '')
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

# Dot-sourcing exposes only the parser for offline behavioral validation.
if ($MyInvocation.InvocationName -eq '.') { return }

$record = [ordered]@{
    schema_version = 1
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    apk_path = $ApkPath
    sha256 = $null
    classification = 'unknown'
    admitted = $false
    manifest_sha256 = $null
    tool = $ApkAnalyzer
    reason = $null
}
$code = 3
try {
    if (-not $ApkPath) { throw 'ApkPath is required.' }
    $resolved = (Resolve-Path -LiteralPath $ApkPath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw 'APK must be a file.' }
    $record.apk_path = $resolved
    $record.sha256 = Get-ApkFileSha256 $resolved
    $toolCommand = Get-Command $ApkAnalyzer -ErrorAction Stop
    if ($toolCommand.CommandType -ne 'Application') { throw 'ApkAnalyzer must resolve to an Android SDK executable.' }
    $record.tool = $toolCommand.Source
    if ([System.IO.Path]::GetExtension($toolCommand.Source) -in @('.bat', '.cmd')) {
        if ($resolved -match '[&|<>^%!"\r\n]' -or $toolCommand.Source -match '[&|<>^%!"\r\n]') {
            throw 'Batch-tool paths containing shell metacharacters are unsupported; use a safe artifact and SDK path.'
        }
    }
    $manifest = & $toolCommand.Source manifest print $resolved 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'apkanalyzer manifest print failed.' }
    $afterHash = Get-ApkFileSha256 $resolved
    if ($record.sha256 -ne $afterHash) { throw 'APK changed during classification.' }
    $manifestText = $manifest -join "`n"
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $record.manifest_sha256 = ([BitConverter]::ToString($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($manifestText)))).Replace('-', '')
    } finally { $hasher.Dispose() }
    $record.classification = Get-ApkDebugClassification $manifestText
    switch ($record.classification) {
        'debug' { $code = 0; $record.admitted = $true; $record.reason = 'Packaged manifest explicitly sets android:debuggable=true.' }
        'non-debug' { $code = 2; $record.reason = 'Declined: this APK is a release or non-debug build. This testing workflow only accepts verified debug APKs. Provide a debug build with android:debuggable=true.' }
        default { $record.reason = 'Blocked: the APK debug status could not be verified. No APK testing was performed.' }
    }
} catch {
    $record.reason = 'Blocked: the APK debug status could not be verified. No APK testing was performed. ' + $_.Exception.Message
}
$json = $record | ConvertTo-Json -Depth 4
if ($OutputPath) {
    try {
        $fullOutput = [System.IO.Path]::GetFullPath($OutputPath)
        if ($record.apk_path -and $fullOutput -eq $record.apk_path) { throw 'OutputPath must not overwrite the APK.' }
        if (Test-Path -LiteralPath $fullOutput) { throw 'OutputPath already exists; use a new gate evidence filename.' }
        $parent = Split-Path -Parent $fullOutput
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        $stream = [System.IO.File]::Open($fullOutput, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.WriteLine($json) } finally { $writer.Dispose() }
    } catch {
        Write-Error ('Unable to save gate evidence: ' + $_.Exception.Message)
        exit 3
    }
}
Write-Output $json
exit $code
