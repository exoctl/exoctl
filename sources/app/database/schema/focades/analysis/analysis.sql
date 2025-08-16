-- Table: analysis
CREATE TABLE IF NOT EXISTS analysis (
    id INTEGER PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(100),
    sha256 VARCHAR(64),
    sha1 VARCHAR(40),
    sha512 VARCHAR(128),
    sha224 VARCHAR(56),
    sha384 VARCHAR(96),
    sha3_256 VARCHAR(64),
    sha3_512 VARCHAR(128),
    file_size BIGINT,
    file_entropy DOUBLE PRECISION,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT,
    is_malicious BOOLEAN,
    packed BOOLEAN,
    owner VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS analysis_info (
    metadata_id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name VARCHAR(100) NOT NULL,
    version INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_analysis_timestamp
AFTER UPDATE ON analysis
FOR EACH ROW
BEGIN
    UPDATE analysis SET last_update_date = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;

CREATE TRIGGER update_analysis_info_timestamp
AFTER UPDATE ON analysis_info
FOR EACH ROW
BEGIN
    UPDATE analysis_info SET updated_at = CURRENT_TIMESTAMP WHERE metadata_id = OLD.metadata_id;
END;