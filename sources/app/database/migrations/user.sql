-- Criação da tabela de log
CREATE TABLE IF NOT EXISTS user_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    email TEXT,
    action TEXT,
    action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trigger para registrar inserções na tabela user
CREATE TRIGGER IF NOT EXISTS trg_log_user_insert
AFTER INSERT ON users
BEGIN
    INSERT INTO user_log (user_id, username, email, action)
    VALUES (NEW.id, NEW.username, NEW.email, 'INSERT');
END;
