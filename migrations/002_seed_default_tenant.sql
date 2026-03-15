INSERT INTO tenants (name)
SELECT 'Default Tenant'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE name = 'Default Tenant');
