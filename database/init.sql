CREATE DATABASE IF NOT EXISTS devfolio;
USE devfolio;

GRANT ALL PRIVILEGES ON devfolio.* TO 'root'@'%' IDENTIFIED BY 'root';

CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    bio TEXT,
    role VARCHAR(50) DEFAULT 'USER',
    avatar_url VARCHAR(500)
);

CREATE TABLE IF NOT EXISTS projects (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    description TEXT,
    github_url VARCHAR(500),
    image_url VARCHAR(500),
    owner_id BIGINT,
    is_public BOOLEAN DEFAULT true,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

INSERT INTO users (email, password, role, bio) VALUES
        ('admin@devfolio.com', '$2a$12$kByPS9JGahXs9qK/PSy0CetsoknZYnXm3btfs9kD6gr5wwvHrsHAe', 'ADMIN', '<h1>Admin</h1>'),
        ('alice@student.com', '$2a$12$kByPS9JGahXs9qK/PSy0CetsoknZYnXm3btfs9kD6gr5wwvHrsHAe', 'USER', 'Développeuse passionnée'),
        ('bob@student.com', '$2a$12$kByPS9JGahXs9qK/PSy0CetsoknZYnXm3btfs9kD6gr5wwvHrsHAe', 'USER', 'Étudiant en alternance');


INSERT INTO projects (title, description, github_url, owner_id, is_public) VALUES
    ('Mon Portfolio', 'Mon premier projet Vue.js', 'https://github.com/alice/portfolio', 2, true),
    ('API REST Spring', 'Backend pour mon app', 'https://github.com/bob/api', 3, false),
    ('Projet Secret', 'Données confidentielles du client XYZ — NDA signé',
     'https://github.com/bob/secret', 3, false);
