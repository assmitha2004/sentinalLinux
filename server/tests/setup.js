// Test env must be set before any app module (config) is imported.
process.env.MONGODB_URI = process.env.MONGODB_URI_TEST || 'mongodb://127.0.0.1:27017/sentinelai_test';
process.env.JWT_SECRET = 'test-secret-test-secret-test-secret-123456';
process.env.NODE_ENV = 'test';
process.env.AI_PROVIDER = '';
process.env.ML_MIN_SAMPLES = '50';
