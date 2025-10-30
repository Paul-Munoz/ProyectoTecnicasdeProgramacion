#!/usr/bin/env python3
# test_connection.py - Script para probar la conexión a MySQL

import mysql.connector
from mysql.connector import Error

def test_connection():
    """Prueba la conexión a la base de datos GestionAlimentos."""
    try:
        # Configuración de conexión
        config = {
            'host': 'localhost',
            'user': 'root',
            'password': '',  # Contraseña vacía para root local
            'database': 'GestionAlimentos',
            'port': '3306',
            'connection_timeout': 10,
            'auth_plugin': 'mysql_native_password'
        }

        print("🔍 Probando conexión a MySQL...")
        print(f"📍 Host: {config['host']}")
        print(f"👤 Usuario: {config['user']}")
        print(f"🗄️ Base de datos: {config['database']}")
        print(f"🔌 Puerto: {config['port']}")

        # Intentar conexión
        connection = mysql.connector.connect(**config)

        if connection.is_connected():
            db_info = connection.get_server_info()
            print("✅ ¡Conexión exitosa!")
            print(f"📊 Versión del servidor MySQL: {db_info}")

            # Probar consulta simple
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT VERSION() as version")
            result = cursor.fetchone()
            print(f"🔢 Versión completa: {result['version']}")

            # Verificar usuarios
            cursor.execute("SELECT COUNT(*) as total FROM usuarios")
            users = cursor.fetchone()
            print(f"👥 Usuarios en la base de datos: {users['total']}")

            # Listar usuarios disponibles
            cursor.execute("SELECT nombreusuario, rol FROM usuarios WHERE activo = TRUE")
            usuarios = cursor.fetchall()
            print("\n📋 Usuarios disponibles:")
            for user in usuarios:
                print(f"   - {user['nombreusuario']} ({user['rol']})")

            cursor.close()
            connection.close()
            print("🔌 Conexión cerrada correctamente.")
            return True

    except Error as e:
        print(f"❌ Error de conexión: {e}")
        print("\n🔧 DIAGNÓSTICO PROFESIONAL:")
        print("=" * 50)

        # Análisis específico del error
        error_str = str(e).lower()
        if "access denied" in error_str:
            print("🔐 PROBLEMA DE AUTENTICACIÓN:")
            print("   • Usuario o contraseña incorrectos")
            print("   • El usuario 'root' puede requerir contraseña")
            print("   • Pruebe cambiar password='' por password='password123'")
        elif "connection refused" in error_str or "can't connect" in error_str:
            print("🔌 PROBLEMA DE CONECTIVIDAD:")
            print("   • MySQL Server no está ejecutándose")
            print("   • Puerto 3306 bloqueado o incorrecto")
            print("   • Firewall bloqueando conexiones")
        elif "unknown database" in error_str:
            print("🗄️ PROBLEMA DE BASE DE DATOS:")
            print("   • La base de datos 'GestionAlimentos' no existe")
            print("   • Necesita crear la base de datos primero")
        else:
            print("⚠️ ERROR GENÉRICO:")
            print("   • Revise la configuración de MySQL")

        print("\n📋 PASOS DE SOLUCIÓN DETALLADOS:")
        print("=" * 50)
        print("1. VERIFICAR MYSQL SERVER:")
        print("   • Terminal: brew services list")
        print("   • Buscar: mysql (debe estar 'started')")
        print("   • Si no: brew services start mysql")
        print("   • Esperar 10-15 segundos")
        print()
        print("2. VERIFICAR CREDENCIALES:")
        print("   • Usuario: root")
        print("   • Contraseña: '' (vacía) o 'password123'")
        print("   • Probar: mysql -u root -p")
        print()
        print("3. CREAR BASE DE DATOS:")
        print("   • mysql -u root -p")
        print("   • CREATE DATABASE GestionAlimentos;")
        print("   • SHOW DATABASES; (verificar)")
        print()
        print("4. IMPORTAR ESTRUCTURA:")
        print("   • mysql -u root GestionAlimentos < GestionAlimentos.sql")
        print("   • Verificar tablas: USE GestionAlimentos; SHOW TABLES;")
        print()
        print("5. PROBAR CONEXIÓN:")
        print("   • python test_connection.py")
        print()
        print("6. SI PERSISTE:")
        print("   • Revisar: /usr/local/var/mysql/*.err")
        print("   • Reset root: brew services stop mysql")
        print("   • mysql_secure_installation")
        return False
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        return False

if __name__ == "__main__":
    print("🧪 PRUEBA DE CONEXIÓN A MYSQL")
    print("=" * 40)
    success = test_connection()
    print("=" * 40)
    if success:
        print("🎉 ¡La conexión funciona correctamente!")
        print("💡 Ahora puede ejecutar Gestion_Alimentos.py")
    else:
        print("⚠️ La conexión falló. Revise la configuración.")