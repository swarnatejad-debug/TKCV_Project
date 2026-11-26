PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exams (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id      INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    topic         TEXT NOT NULL,
    subject_code  TEXT NOT NULL UNIQUE,
    num_questions INTEGER NOT NULL DEFAULT 0,
    marks_per_q   INTEGER NOT NULL DEFAULT 1,
    duration_min  INTEGER NOT NULL DEFAULT 30,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS questions (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    text    TEXT NOT NULL,
    opt_a   TEXT NOT NULL,
    opt_b   TEXT NOT NULL,
    opt_c   TEXT NOT NULL,
    opt_d   TEXT NOT NULL,
    correct TEXT NOT NULL CHECK (correct IN ('A','B','C','D'))
);

CREATE TABLE IF NOT EXISTS attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    exam_id      INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    usn          TEXT NOT NULL,
    roll_no      TEXT NOT NULL,
    phone        TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    submitted_at INTEGER,
    score        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (exam_id, usn)
);

CREATE TABLE IF NOT EXISTS answers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id  INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
    question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    chosen      TEXT NOT NULL CHECK (chosen IN ('A','B','C','D'))
);

CREATE INDEX IF NOT EXISTS idx_questions_exam ON questions(exam_id);
CREATE INDEX IF NOT EXISTS idx_attempts_exam  ON attempts(exam_id);
CREATE INDEX IF NOT EXISTS idx_answers_attempt ON answers(attempt_id);
