-- Innovation RS Database Schema
-- Run this file: mysql -u root -p innovation_rs_jobs < schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('seeker', 'poster', 'admin') DEFAULT 'seeker',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX(email), INDEX(role)
);

CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  paypal_order_id VARCHAR(255) UNIQUE,
  amount DECIMAL(10, 2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  plan_type ENUM('sme', 'ent', 'executive', 'custom') DEFAULT 'custom',
  status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'pending',
  client_email VARCHAR(255),
  custom_link_token VARCHAR(64),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  INDEX(status), INDEX(created_at), INDEX(plan_type), INDEX(custom_link_token)
);

CREATE TABLE IF NOT EXISTS bills (
  id INT AUTO_INCREMENT PRIMARY KEY,
  payment_id INT UNIQUE NOT NULL,
  bill_number VARCHAR(50) UNIQUE,
  user_id INT,
  client_name VARCHAR(255),
  client_email VARCHAR(255),
  amount DECIMAL(10, 2),
  currency VARCHAR(3),
  plan_type VARCHAR(50),
  description TEXT,
  issued_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  due_date DATE,
  paid_date TIMESTAMP,
  sent_via_email TINYINT DEFAULT 0,
  FOREIGN KEY (payment_id) REFERENCES payments(id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  INDEX(bill_number), INDEX(client_email), INDEX(paid_date)
);

CREATE TABLE IF NOT EXISTS jobs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  poster_id INT NOT NULL,
  payment_id INT,
  icon LONGBLOB,
  title VARCHAR(255) NOT NULL,
  description LONGTEXT,
  apply_link VARCHAR(500),
  approved TINYINT DEFAULT 0,
  views INT DEFAULT 0,
  post_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NULL,
  FOREIGN KEY (poster_id) REFERENCES users(id),
  FOREIGN KEY (payment_id) REFERENCES payments(id),
  INDEX(approved), INDEX(post_time), INDEX(poster_id)
);

CREATE TABLE IF NOT EXISTS tags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS job_tags (
  job_id INT NOT NULL,
  tag_id INT NOT NULL,
  PRIMARY KEY (job_id, tag_id),
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Sample admin user (password: admin123)
-- Run after schema: UPDATE users SET role='admin' WHERE email='admin@innovation-rs.com';
INSERT IGNORE INTO users (name, email, password_hash, role) 
VALUES ('Admin', 'admin@innovation-rs.com', '$2b$10$EIZWJJKqxBrInfwJaKzKF.qxb5l/uI0fU7iM4HJvgL0M8w4HtS0pa', 'admin');
