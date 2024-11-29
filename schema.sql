CREATE TABLE user (
  id TEXT UNIQUE PRIMARY KEY,
  provider TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  profile_pic TEXT NOT NULL
);
