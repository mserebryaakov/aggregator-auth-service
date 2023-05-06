CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE roles 
(
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  code VARCHAR(255)
);

CREATE TABLE users 
(
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  email VARCHAR(255),
  password VARCHAR(255),
  name VARCHAR(255),
  surname VARCHAR(255),
  address VARCHAR(255) DEFAULT NULL,
  role UUID REFERENCES roles(id) DEFAULT NULL
);