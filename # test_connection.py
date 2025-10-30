# test_connection.py
import mysql.connector
from mysql.connector import Error

def test_mysql_connection():
    try:
        print("🔍 Probando conexión a MySQL...")
        
        # Intentar conectar sin especificar base de datos primero
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=''  # Si tienes contraseña, colócala aquí
        )
        
        if connection.is_connected():
            print("✅ Conectado a MySQL Server")
            
            # Verificar si la base de datos existe
            cursor = connection.cursor()
            cursor.execute("SHOW DATABASES LIKE 'GestionAlimentos'")
            result = cursor.fetchone()
            
            if result:
                print("✅ Base de datos 'GestionAlimentos' encontrada")
                
                # Conectar a la base de datos específica
                connection.database = 'GestionAlimentos'
                cursor.execute("SHOW TABLES")
                tables = cursor.fetchall()
                
                print(f"✅ Tablas en la base de datos: {len(tables)}")
                for table in tables:
                    print(f"   - {table[0]}")
                    
            else:
                print("❌ Base de datos 'GestionAlimentos' NO encontrada")
                
            cursor.close()
            connection.close()
            
    except Error as e:
        print(f"❌ Error de conexión: {e}")
        print("\nPosibles soluciones:")
        print("1. Verifica que MySQL esté ejecutándose")
        print("2. Verifica el usuario y contraseña")
        print("3. Verifica que la base de datos 'GestionAlimentos' exista")

if __name__ == "__main__":
    test_mysql_connection()