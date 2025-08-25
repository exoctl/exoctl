CREATE TABLE IF NOT EXISTS analysis_tags (
    analysis_id INTEGER,
    tag_id INTEGER,
    PRIMARY KEY (analysis_id, tag_id),
    FOREIGN KEY (analysis_id) REFERENCES analysis(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);