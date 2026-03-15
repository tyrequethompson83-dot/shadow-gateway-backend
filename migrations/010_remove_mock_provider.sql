PRAGMA foreign_keys = ON;

DELETE FROM tenant_provider_keys WHERE provider = 'mock';
DELETE FROM tenant_provider_configs WHERE provider = 'mock';
