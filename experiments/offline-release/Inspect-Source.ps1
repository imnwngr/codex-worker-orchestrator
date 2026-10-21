. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$identity = Get-SourceIdentity $repository
@{status='INSPECTION_ONLY_NOT_APPROVAL';sourceRevision=$identity.sourceRevision;sourceContentSha256=$identity.sourceContentSha256;
    identityAlgorithm='SHA256_ORDINAL_MODE_PATH_RAW_FILE_SHA256_LF_JOIN_V1';files=$identity.files;
    instruction='Compare this identity with independently reviewed delivery evidence; do not automatically trust locally discovered pins.'} | ConvertTo-Json
