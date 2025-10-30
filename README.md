<<<<<<< HEAD
# Sistema de Gestión de Alimentos 

## Descripción del Proyecto

Este es un sistema completo de gestión empresarial desarrollado en Python utilizando PyQt5 para la interfaz gráfica y MySQL como base de datos. El sistema está diseñado para el control de proveedores y listas de precios de productos alimenticios, implementando funcionalidades avanzadas de gestión empresarial.

## Características Principales

### 🔐 Sistema de Acceso Restringido
- Autenticación segura con roles de usuario diferenciados
- Control de permisos por módulos según el rol del usuario
- Encriptación de contraseñas con bcrypt
- Bloqueo temporal por intentos fallidos de login

### 📦 Gestión de Productos e Inventario
- Altas, bajas y modificaciones de productos
- Control de stock mínimo y alertas
- Categorización de productos
- Códigos de barras opcionales
- Historial de precios

### 🚚 Gestión de Proveedores
- Registro completo de proveedores (RUC, contacto, dirección)
- Altas, bajas y modificaciones
- Validación de datos empresariales

### 📈 Variaciones de Precios por IPC
- Aplicación automática de ajustes por Índice de Precios al Consumidor
- Historial completo de ajustes IPC
- Cálculos precisos con decimales
- Auditoría de cambios

### 📑 Sistema de Comprobantes
- Registro de compras, ventas y notas de ingreso/salida
- Detalles de productos por comprobante
- Actualización automática de stock
- Salida de comprobantes por pantalla
- Impresión en PDF

### 📊 Dashboard y Reportes
- Estadísticas en tiempo real del sistema
- Gráficos interactivos (productos por categoría, valor de inventario)
- Exportación a Excel
- Reportes personalizados

### 🛡️ Seguridad Empresarial
- Logs de auditoría completos
- Validaciones de negocio
- Manejo de errores robusto
- Backup y recuperación

## Arquitectura del Sistema

### Componentes Principales

1. **DatabaseManager**: Gestiona la conexión y operaciones con MySQL
2. **SecurityManager**: Maneja autenticación y seguridad
3. **BusinessLogic**: Contiene todas las reglas de negocio y validaciones
4. **UI Components**: Interfaz gráfica moderna con PyQt5
5. **ConfigManager**: Gestión de configuración de la aplicación

### Roles de Usuario

- **Admin**: Acceso completo a todas las funcionalidades
- **Inventario**: Gestión de productos y stock
- **Compras**: Proveedores y comprobantes de compra
- **Finanzas**: IPC y reportes financieros
- **Reportes**: Visualización y exportación de datos
- **Atención al Cliente**: Acceso limitado a consultas

## Requisitos del Sistema

### Software Requerido
- Python 3.8+
- MySQL Server 8.0+
- PyQt5
- mysql-connector-python
- bcrypt
- matplotlib
- reportlab
- openpyxl (opcional, para exportación Excel)

### Instalación de Dependencias

```bash
pip install PyQt5 mysql-connector-python bcrypt matplotlib reportlab openpyxl
```

### Configuración de Base de Datos

1. Instalar MySQL Server
2. Crear base de datos:
```sql
CREATE DATABASE GestionAlimentos;
```
3. Importar estructura:
```bash
mysql -u root GestionAlimentos < GestionAlimentos.sql
```

## Instalación y Ejecución

1. **Clonar o descargar** los archivos del proyecto
2. **Instalar dependencias** como se indica arriba
3. **Configurar MySQL** y crear la base de datos
4. **Ejecutar el programa**:
```bash
python Gestion_Alimentos.py
```

### Usuarios de Prueba

El sistema incluye usuarios de prueba preconfigurados:

- **Administradores**: paul, ana (contraseña: admin123)
- **Inventario**: jhon (contraseña: admin123)
- **Compras**: yessenia (contraseña: admin123)
- **Finanzas**: piero (contraseña: admin123)
- **Reportes**: cassandra (contraseña: admin123)
- **Atención al Cliente**: vanina, miryam, natalia (contraseña: admin123)

## Estructura del Proyecto

```
├── Gestion_Alimentos.py          # Archivo principal de la aplicación
├── GestionAlimentos.sql          # Script de creación de base de datos
├── test_connection.py            # Script de prueba de conexión
├── README.md                     # Este archivo
└── app_errors.log               # Log de errores (generado automáticamente)
```

## Funcionalidades Detalladas

### Gestión de Proveedores
- Formulario completo con validaciones
- Búsqueda y filtrado
- Exportación a Excel
- Eliminación lógica (inactivación)

### Gestión de Productos
- Formulario detallado con categorías
- Control de stock con alertas visuales
- Aplicación de IPC masiva
- Historial de precios

### Comprobantes
- Creación con detalles de productos
- Actualización automática de inventario
- Impresión en PDF
- Visualización de detalles

### Dashboard
- Estadísticas en tiempo real
- Gráficos de análisis
- Indicadores clave de rendimiento

## Consideraciones Técnicas

### Seguridad
- Hashing de contraseñas con bcrypt
- Validaciones de entrada
- Logs de auditoría
- Control de sesiones

### Rendimiento
- Cache inteligente para consultas frecuentes
- Conexiones optimizadas a BD
- Procesamiento por lotes para operaciones masivas

### Escalabilidad
- Arquitectura modular
- Separación de responsabilidades
- Fácil extensión de funcionalidades

## Trabajo Práctico - Técnicas de Programación

**Carrera:** Ciencia de Datos e Inteligencia Artificial  
**Institución:** IFTS 24  
**Materia:** Técnicas de Programación  

### Consigna del Trabajo Práctico

Crear un programa para el control de proveedores y listas de precios de productos alimenticios teniendo en cuenta los siguientes aspectos:

1. **El sistema debe ser de acceso restringido** sólo para algunas opciones especiales (a considerar según el grupo de trabajo)
2. **Variaciones de precios según IPC**
3. **Salida de comprobantes por pantalla**
4. **Altas, bajas y modificaciones de proveedores**

### Implementación Realizada

✅ **Acceso Restringido**: Sistema de roles con permisos diferenciados  
✅ **IPC**: Módulo completo de ajustes por IPC con historial  
✅ **Comprobantes**: Sistema de comprobantes con impresión por pantalla  
✅ **CRUD Proveedores**: Altas, bajas y modificaciones completas  

### Tecnologías Utilizadas
- **Lenguaje**: Python 3.8+
- **GUI**: PyQt5
- **Base de Datos**: MySQL
- **Seguridad**: bcrypt para hashing
- **Reportes**: reportlab para PDF, openpyxl para Excel
- **Gráficos**: matplotlib

## Soporte y Contacto

Para soporte técnico o consultas sobre el sistema, contactar al equipo de desarrollo.

## Licencia

Este proyecto es desarrollado como trabajo práctico académico para el IFTS 24.
=======
# ProyectoTecnicasdeProgramacion
Aplicación de gestión de alimentos creada como proyecto académico. Incluye registro, búsqueda y control de productos.
>>>>>>> d45cc7a1944843cd2110b2ba944c380722410bbd
