#!/usr/bin/env python3
# Test para verificar funcionamiento de barcode

try:
    from barcode import get_barcode_class
    from barcode.writer import ImageWriter
    
    # Crear código de barras
    Code128 = get_barcode_class('code128')
    code = Code128('123456789012', writer=ImageWriter())
    
    # Guardar como imagen
    code.save('/Users/paulrichardmunozbruno/Desktop/test_barcode')
    print("✅ Código de barras creado exitosamente")
    
except ImportError as e:
    print(f"❌ Error de importación: {e}")
except Exception as e:
    print(f"❌ Error: {e}")