-- GestionAlimentos.sql - VERSIÓN COMPLETAMENTE CORREGIDA
DROP DATABASE IF EXISTS GestionAlimentos;
CREATE DATABASE GestionAlimentos;
USE GestionAlimentos;

-- ==========================
-- Tabla: usuarios
-- ==========================
CREATE TABLE usuarios (
    idusuario INT PRIMARY KEY AUTO_INCREMENT,
    nombreusuario VARCHAR(50) NOT NULL UNIQUE,
    contrasena VARCHAR(100) NOT NULL,
    rol VARCHAR(20) NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    email VARCHAR(100),
    telefono VARCHAR(20),
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ultimo_login TIMESTAMP NULL,
    estaciontrabajo VARCHAR(50)
);

-- ==========================
-- Tabla: proveedores
-- ==========================
CREATE TABLE proveedores (
    idproveedor INT PRIMARY KEY AUTO_INCREMENT,
    nombre VARCHAR(100) NOT NULL UNIQUE,
    contacto VARCHAR(100),
    telefono VARCHAR(20),
    email VARCHAR(100),
    direccion VARCHAR(255),
    ruc VARCHAR(20) UNIQUE,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE
);

-- ==========================
-- Tabla: productos
-- ==========================
CREATE TABLE productos (
    idproducto INT PRIMARY KEY AUTO_INCREMENT,
    idproveedor INT NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    descripcion TEXT,
    categoria VARCHAR(50),
    stock INT NOT NULL DEFAULT 0,
    stockminimo INT DEFAULT 10,
    precio DECIMAL(10,2) NOT NULL,
    preciobase DECIMAL(10,2),
    codigo_barras VARCHAR(50) UNIQUE,
    fecharegistro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (idproveedor) REFERENCES proveedores(idproveedor) ON DELETE RESTRICT
);

-- ==========================
-- Tabla: historialprecios
-- ==========================
CREATE TABLE historialprecios (
    idhistorial INT PRIMARY KEY AUTO_INCREMENT,
    idproducto INT NOT NULL,
    precioanterior DECIMAL(10,2),
    preccionuevo DECIMAL(10,2),
    fechacambio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    motivo VARCHAR(200),
    tipocambio VARCHAR(50),
    usuariocambio VARCHAR(50),
    FOREIGN KEY (idproducto) REFERENCES productos(idproducto) ON DELETE CASCADE
);

-- ==========================
-- Tabla: controlipc
-- ==========================
CREATE TABLE controlipc (
    idipc INT PRIMARY KEY AUTO_INCREMENT,
    mes VARCHAR(20) NOT NULL,
    anio INT NOT NULL,
    porcentajeipc DECIMAL(5,2) NOT NULL,
    fechaaplicacion DATE,
    aplicado BOOLEAN DEFAULT FALSE,
    usuarioaplicacion VARCHAR(50),
    fecharegistro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================
-- Tabla: comprobantes
-- ==========================
CREATE TABLE comprobantes (
    idcomprobante INT PRIMARY KEY AUTO_INCREMENT,
    tipo_doc VARCHAR(20) NOT NULL,
    serie VARCHAR(20) NOT NULL,
    numero VARCHAR(50) NOT NULL,
    idproveedor INT,
    fecha_doc DATE NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    fechacreacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    estado VARCHAR(20) DEFAULT 'EMITIDO',
    FOREIGN KEY (idproveedor) REFERENCES proveedores(idproveedor) ON DELETE SET NULL,
    UNIQUE KEY unique_serie_numero (serie, numero)
);

-- ==========================
-- Tabla: detallecomprobantes
-- ==========================
CREATE TABLE detallecomprobantes (
    iddetallecomprobante INT PRIMARY KEY AUTO_INCREMENT,
    idcomprobante INT NOT NULL,
    idproducto INT NOT NULL,
    cantidad INT NOT NULL,
    precio_unitario DECIMAL(10,2) NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (idcomprobante) REFERENCES comprobantes(idcomprobante) ON DELETE CASCADE,
    FOREIGN KEY (idproducto) REFERENCES productos(idproducto) ON DELETE RESTRICT
);

-- ==========================
-- Tabla: audit_log
-- ==========================
CREATE TABLE audit_log (
    idlog INT PRIMARY KEY AUTO_INCREMENT,
    usuario VARCHAR(50),
    accion VARCHAR(100),
    detalles TEXT,
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================
-- INSERTAR USUARIOS DEL SISTEMA - CONTRASEÑA: admin123
-- ==========================
INSERT INTO usuarios (nombreusuario, contrasena, rol, email, telefono, estaciontrabajo) VALUES 
('paul', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'admin', 'paul@empresa.com', '999888777', 'Administración Central'),
('ana', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'admin', 'ana@empresa.com', '999888776', 'Administración Central'),
('jhon', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'inventario', 'jhon@empresa.com', '999888775', 'Almacén Principal'),
('yessenia', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'compras', 'yessenia@empresa.com', '999888774', 'Compras y Abastecimiento'),
('piero', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'finanzas', 'piero@empresa.com', '999888773', 'Finanzas'),
('cassandra', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'reportes', 'cassandra@empresa.com', '999888772', 'Análisis de Datos'),
('vanina', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'atencion_cliente', 'vanina@empresa.com', '999888771', 'Atención 01'),
('miryam', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'atencion_cliente', 'miryam@empresa.com', '999888770', 'Atención 02'),
('natalia', '$2b$12$LQv3c1yqBzwSxJ4T4YwZeuY6n6b9s8JZ8VkQdE7fM5rNkYbLd8HKO', 'atencion_cliente', 'natalia@empresa.com', '999888769', 'Atención 03');

-- ==========================
-- INSERTAR PROVEEDORES DE PRUEBA
-- ==========================
INSERT INTO proveedores (nombre, contacto, telefono, email, direccion, ruc) VALUES 
('Distribuidora La Huerta SA', 'Maria Perez', '11112222', 'huerta@empresa.com', 'Av. Los Alamos 123 - Lima', '20100055551'),
('Frutas del Valle SAC', 'Carlos López', '22223333', 'frutas@empresa.com', 'Calle Las Frutas 456 - Arequipa', '20100055552'),
('Carnes Selectas EIRL', 'Ana Torres', '33334444', 'carnes@empresa.com', 'Jr. Carnicería 789 - Trujillo', '20100055553'),
('Lácteos Andinos', 'Roberto Díaz', '44445555', 'lacteos@empresa.com', 'Av. Lácteos 321 - Cusco', '20100055554'),
('Granos Nacionales', 'Lucía Mendoza', '55556666', 'granos@empresa.com', 'Calle Los Granos 654 - Piura', '20100055555');

-- ==========================
-- INSERTAR PRODUCTOS DE PRUEBA
-- ==========================
INSERT INTO productos (idproveedor, nombre, descripcion, categoria, stock, stockminimo, precio, preciobase, codigo_barras) VALUES 
(1, 'Manzana Roja Premium', 'Manzana roja premium importada de Chile', 'Frutas', 150, 20, 180.00, 150.00, '750100000001'),
(1, 'Papa Huayro', 'Papa huayro de la sierra peruana', 'Tubérculos', 200, 30, 95.00, 80.00, '750100000002'),
(2, 'Banana Orgánica', 'Banana orgánica de Tarapoto', 'Frutas', 300, 25, 140.00, 120.00, '750100000003'),
(2, 'Naranja Valencia', 'Naranja valencia jugosa sin semillas', 'Frutas', 180, 15, 115.00, 100.00, '750100000004'),
(3, 'Carne de Res Premium', 'Corte premium de res para bistec', 'Carnes', 50, 5, 1100.00, 950.00, '750100000005'),
(3, 'Pollo Entero Fresco', 'Pollo entero fresco granja', 'Aves', 80, 10, 750.00, 650.00, '750100000006'),
(4, 'Queso Fresco Campesino', 'Queso fresco campesino 1kg', 'Lácteos', 60, 8, 280.00, 250.00, '750100000007'),
(4, 'Yogurt Natural', 'Yogurt natural 1kg sin azúcar', 'Lácteos', 120, 15, 120.00, 100.00, '750100000008'),
(5, 'Arroz Extra', 'Arroz extra grano largo 1kg', 'Granos', 200, 25, 45.00, 40.00, '750100000009'),
(5, 'Lentejas Seleccionadas', 'Lentejas seleccionadas 500g', 'Legumbres', 150, 20, 85.00, 75.00, '750100000010');

-- ==========================
-- VERIFICACIÓN
-- ==========================
SELECT '=== BASE DE DATOS CREADA EXITOSAMENTE ===' as mensaje;
SELECT 'Usuarios: ' as info, COUNT(*) as cantidad FROM usuarios;
SELECT 'Proveedores: ' as info, COUNT(*) as cantidad FROM proveedores;
SELECT 'Productos: ' as info, COUNT(*) as cantidad FROM productos;
SELECT '=== USUARIOS DISPONIBLES ===' as mensaje;
SELECT nombreusuario, rol, activo FROM usuarios;