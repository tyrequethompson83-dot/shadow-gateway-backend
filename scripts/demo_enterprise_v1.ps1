param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$DemoUser = "tyreque"
)

$ErrorActionPreference = "Stop"

Write-Host "1) Create tenant 2..."
$tenantCreateOut = & .\.venv\Scripts\python.exe scripts\create_tenant.py "Tenant 2"
Write-Host $tenantCreateOut

$tenant2Id = 2
if ($tenantCreateOut -match "id=(\d+)") {
    $tenant2Id = [int]$Matches[1]
}

Write-Host "2) Grant $DemoUser admin in tenant 1 and tenant $tenant2Id (bootstrap via DB helper)..."
@'
import sys
from enterprise.db_enterprise import ensure_enterprise_schema, ensure_user, upsert_membership

user = sys.argv[1]
t1 = int(sys.argv[2])
t2 = int(sys.argv[3])
ensure_enterprise_schema()
uid = ensure_user(user)
upsert_membership(t1, uid, "admin")
upsert_membership(t2, uid, "admin")
print(f"granted admin for user={user} in tenants {t1} and {t2}")
'@ | .\.venv\Scripts\python.exe - $DemoUser 1 $tenant2Id

$headersTenant1 = @{
    "X-User" = $DemoUser
    "X-Tenant-Id" = "1"
}
$headersTenant2 = @{
    "X-User" = $DemoUser
    "X-Tenant-Id" = "$tenant2Id"
}

Write-Host "3) Send 3 requests for tenant 1..."
1..3 | ForEach-Object {
    $body = @{
        prompt = "Tenant1 prompt #$_"
        purpose = "enterprise-v1-demo"
    } | ConvertTo-Json
    $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/chat" -Headers $headersTenant1 -ContentType "application/json" -Body $body
    Write-Host "tenant1 request_id: $($resp.request_id)"
}

Write-Host "4) Send 1 request for tenant $tenant2Id..."
$body2 = @{
    prompt = "Tenant2 prompt #1"
    purpose = "enterprise-v1-demo"
} | ConvertTo-Json
$resp2 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/chat" -Headers $headersTenant2 -ContentType "application/json" -Body $body2
Write-Host "tenant2 request_id: $($resp2.request_id)"

Write-Host "5) Show tenant-specific summaries..."
$sum1 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/summary" -Headers $headersTenant1
$sum2 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/summary" -Headers $headersTenant2
Write-Host "tenant1 summary: $($sum1 | ConvertTo-Json -Compress)"
Write-Host "tenant$tenant2Id summary: $($sum2 | ConvertTo-Json -Compress)"

Write-Host "6) Queue export job for tenant 1..."
$jobResp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/admin/exports" -Headers $headersTenant1
$jobId = $jobResp.job_id
Write-Host "job_id: $jobId"

Write-Host "7) Poll job until done..."
$maxWait = 60
$status = "queued"
for ($i = 0; $i -lt $maxWait; $i++) {
    Start-Sleep -Seconds 1
    $job = Invoke-RestMethod -Method Get -Uri "$BaseUrl/admin/jobs/$jobId" -Headers $headersTenant1
    $status = $job.item.status
    Write-Host "job status: $status"
    if ($status -eq "done" -or $status -eq "failed") { break }
}
if ($status -ne "done") {
    throw "Export job did not complete successfully. Final status=$status"
}

Write-Host "8) Download export..."
New-Item -ItemType Directory -Force -Path reports | Out-Null
$outFile = "reports\demo_export_tenant1.pdf"
Invoke-WebRequest -Method Get -Uri "$BaseUrl/admin/exports/$jobId/download" -Headers $headersTenant1 -OutFile $outFile
Write-Host "downloaded: $outFile"

Write-Host "9) Verify audit chain for tenant 1 and tenant $tenant2Id..."
& .\.venv\Scripts\python.exe scripts\verify_audit_chain.py --tenant-id 1 --limit 500
& .\.venv\Scripts\python.exe scripts\verify_audit_chain.py --tenant-id $tenant2Id --limit 500

Write-Host ""
Write-Host "Enterprise v1 demo complete."
