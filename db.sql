
CREATE TABLE artists (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    birth_year INT,
    country VARCHAR(255)
) engine=innoDB;

CREATE TABLE artworks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    year_created INT,
    medium VARCHAR(255),
    artist_id INT,
    FOREIGN KEY (artist_id) REFERENCES artists(id)
) engine=innoDB;;

CREATE TABLE exhibitions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    start_date DATE,
    end_date DATE
) engine=innoDB;;

CREATE TABLE sales (
    id INT AUTO_INCREMENT PRIMARY KEY,
    artwork_id INT,
    exhibition_id INT,
    sale_date DATE,
    price DECIMAL(10,2),
    FOREIGN KEY (artwork_id) REFERENCES artworks(id),
    FOREIGN KEY (exhibition_id) REFERENCES exhibitions(id)
) engine=innoDB;


CREATE TABLE artwork_exhibitions (
    artwork_id INT,
    exhibition_id INT,
    FOREIGN KEY (artwork_id) REFERENCES artworks(id),
    FOREIGN KEY (exhibition_id) REFERENCES exhibitions(id),
    PRIMARY KEY (artwork_id, exhibition_id)
)engine=innoDB;


INSERT INTO artists (name, birth_year, country) VALUES
('Pablo Picasso', 1881, 'Spain'),
('Vincent van Gogh', 1853, 'Netherlands'),
('Leonardo da Vinci', 1452, 'Italy'),
('Claude Monet', 1840, 'France'),
('Salvador Dali', 1904, 'Spain');

INSERT INTO artworks (title, year_created, medium, artist_id) VALUES
('Guernica', 1937, 'Oil on canvas', 1),
('Starry Night', 1889, 'Oil on canvas', 2),
('Mona Lisa', 1503, 'Oil on wood panel', 3),
('Water Lilies', 1899, 'Oil on canvas', 4),
('The Persistence of Memory', 1931, 'Oil on canvas', 5);

INSERT INTO exhibitions (name, start_date, end_date) VALUES
('Masterpieces of Modern Art', '2022-01-10', '2022-03-01'),
('Impressionist Treasures', '2022-04-05', '2022-06-30'),
('European Art Through the Ages', '2022-07-15', '2022-10-15');

INSERT INTO sales (artwork_id, exhibition_id, sale_date, price) VALUES
(1, 1, '2022-01-20', 12000000),
(2, 1, '2022-02-14', 15000000),
(3, 3, '2022-08-10', 90000000),
(4, 2, '2022-05-30', 8000000),
(5, 1, '2022-02-28', 5500000);


INSERT INTO artwork_exhibitions (artwork_id, exhibition_id)
VALUES (1, 1),
       (2, 1),
       (3, 1),
       (4, 2),
       (5, 2);

CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(255) NOT NULL,
    description VARCHAR(255)
);

-- Insert some roles
INSERT INTO roles (role_name, description) VALUES
    ('admin', 'Administrator with full access'),
    ('manager', 'Manager with moderate access'),
    ('staff', 'Staff with limited access'),
    ('guest', 'Guest with minimal access');

-- Create a users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role_id INT,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

