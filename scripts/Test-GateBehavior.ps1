$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Test-DebugApk.ps1')
$prefix = '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
$cases = @(
    @{ Xml = ($prefix + '<application android:debuggable="true" /></manifest>'); Expected = 'debug' },
    @{ Xml = ($prefix + '<application android:debuggable="false" /></manifest>'); Expected = 'non-debug' },
    @{ Xml = ($prefix + '<application /></manifest>'); Expected = 'non-debug' },
    @{ Xml = ($prefix + '<application debuggable="true" /></manifest>'); Expected = 'non-debug' },
    @{ Xml = ($prefix + '<application android:debuggable="@bool/debug" /></manifest>'); Expected = 'unknown' },
    @{ Xml = ($prefix + '<application android:debuggable="TRUE" /></manifest>'); Expected = 'unknown' },
    @{ Xml = '<broken'; Expected = 'unknown' },
    @{ Xml = ($prefix + '</manifest>'); Expected = 'unknown' },
    @{ Xml = ($prefix + '<application android:debuggable="true" /><application /></manifest>'); Expected = 'unknown' },
    @{ Xml = '<!DOCTYPE manifest [<!ENTITY flag "true">]><manifest><application /></manifest>'; Expected = 'unknown' }
)
foreach ($case in $cases) {
    $actual = Get-ApkDebugClassification $case.Xml
    if ($actual -ne $case.Expected) { throw "Expected $($case.Expected), received $actual" }
}
Write-Output "$($cases.Count) gate classification cases passed."
