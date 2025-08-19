-- Table: analysis
CREATE TABLE IF NOT EXISTS analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name VARCHAR(255) NOT NULL UNIQUE,
    file_type VARCHAR(100),
    sha256 VARCHAR(64) UNIQUE,
    sha1 VARCHAR(40) UNIQUE,
    sha512 VARCHAR(128) UNIQUE,
    sha224 VARCHAR(56) UNIQUE,
    sha384 VARCHAR(96) UNIQUE,
    sha3_256 VARCHAR(64) UNIQUE,
    sha3_512 VARCHAR(128) UNIQUE,
    file_size BIGINT,
    file_entropy DOUBLE PRECISION,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path TEXT,
    is_malicious BOOLEAN,
    is_packed BOOLEAN,
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