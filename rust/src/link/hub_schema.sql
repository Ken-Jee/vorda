CREATE TABLE IF NOT EXISTS invites(verifier TEXT PRIMARY KEY,org TEXT,site TEXT,expires REAL);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,generation TEXT,org TEXT,site TEXT,revoked INTEGER DEFAULT 0,sequence INTEGER DEFAULT 0,received REAL);
        CREATE TABLE IF NOT EXISTS credentials(verifier TEXT PRIMARY KEY,device TEXT,expires REAL);
        CREATE TABLE IF NOT EXISTS batches(device TEXT,sequence INTEGER,digest TEXT,ack BLOB,PRIMARY KEY(device,sequence));
        CREATE TABLE IF NOT EXISTS scans(device TEXT,scan TEXT,PRIMARY KEY(device,scan));
        CREATE TABLE IF NOT EXISTS findings(device TEXT,key TEXT,scope TEXT,payload BLOB,PRIMARY KEY(device,key));
        CREATE TABLE IF NOT EXISTS coverage(device TEXT,scope TEXT,state TEXT,PRIMARY KEY(device,scope));
        CREATE TABLE IF NOT EXISTS audit(at REAL,device TEXT,action TEXT);