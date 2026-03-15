param(
    [string]$BaseUrl = "http://127.0.0.1:8080",
    [string]$UserHeader = "tenant-test-admin"
)

$ErrorActionPreference = "Stop"

Write-Host "1) Creating tenant 2..."
$tenantCreateOut = & .\.venv\Scripts\python.exe scripts\create_tenant.py "Tenant 2"
Write-Host $tenantCreateOut

$tenant2Id = 2
if ($tenantCreateOut -match "id=(\d+)") {
    $tenant2Id = [int]$Matches[1]
}

Write-Host "2) Ensuring test user has admin role in tenant 1 and tenant $tenant2Id..."
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
'@ | .\.venv\Scripts\python.exe - $UserHeader 1 $tenant2Id

Write-Host "3) Sending tenant-scoped chat requests..."
$headersTenant1 = @{
    "X-User" = $UserHeader
    "X-Tenant-Id" = "1"
}
$headersTenant2 = @{
    "X-User" = $UserHeader
    "X-Tenant-Id" = "$tenant2Id"
}

$bodyTenant1 = @{
    prompt = "Tenant 1 data with email alice@example.com"
    purpose = "tenant-1-check"
} | ConvertTo-Json

$bodyTenant2 = @{
    prompt = "Tenant 2 data with ssn 123-45-6789"
    purpose = "tenant-2-check"
} | ConvertTo-Json

$r1 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/chat" -Headers $headersTenant1 -ContentType "application/json" -Body $bodyTenant1
Write-Host "Tenant 1 request_id: $($r1.request_id)"

try {
    $r2 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/chat" -Headers $headersTenant2 -ContentType "application/json" -Body $bodyTenant2
    Write-Host "Tenant 2 request_id: $($r2.request_id)"
} catch {
    # Tenant 2 prompt may be blocked by policy (expected in many configs). Continue.
    Write-Host "Tenant 2 request returned error (often expected for blocked content): $($_.Exception.Message)"
}

Write-Host "4) Verifying request rows in SQLite by tenant..."
@'
import sqlite3
from db import DB_PATH

con = sqlite3.connect(DB_PATH)
rows = con.execute(
    "SELECT tenant_id, COUNT(*) AS c FROM requests GROUP BY tenant_id ORDER BY tenant_id"
).fetchall()
print("requests by tenant:", rows)
con.close()
'@ | .\.venv\Scripts\python.exe -

Write-Host "5) Checking /admin/audit for tenant 1..."
$audit1 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/admin/audit?limit=5" -Headers $headersTenant1
Write-Host "Tenant 1 audit items: $($audit1.count)"

Write-Host "6) Checking /admin/audit for tenant $tenant2Id..."
$audit2 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/admin/audit?limit=5" -Headers $headersTenant2
Write-Host "Tenant $tenant2Id audit items: $($audit2.count)"

Write-Host ""
Write-Host "Verification complete."
Write-Host "- Confirm tenant 1 and tenant $tenant2Id have different request/audit counts."
Write-Host "- In Streamlit, switch tenant dropdown and confirm metrics change."
