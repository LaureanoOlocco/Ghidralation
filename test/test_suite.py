# -*- coding: utf-8 -*-
# test/test_set_name.py
# @category GCL
# @runtime PyGhidra

"""
Test suite inicial para set_name() en Ghidralation.
Ejecutar desde Ghidra con un programa cargado.
"""

import sys
import os
from ghidra.program.model.symbol import SourceType

# Agregar src/ al path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), "src")
sys.path.insert(0, src_dir)

# Configurar currentProgram
import cp

cp.currentProgram = currentProgram

# Información básica del programa cargado
program = currentProgram

# ================================
# Cuadro de bienvenida
# ================================
print(
    f"""
================================================================
                TEST SUITE - (Ghidralation)
----------------------------------------------------------------
Este conjunto de tests valida:
  • Importación de módulos
  • Creación y verificación de símbolos
  • Eliminación de símbolos

Ejecutar con un programa cargado en Ghidra.

=== Información del Programa ===
Nombre del Programa      : {program.getName()}
Ruta del Ejecutable      : {program.getExecutablePath()}
Lenguaje                 : {program.getLanguage()}
Compilador               : {program.getCompilerSpec()}
Dirección Mínima         : {program.getMinAddress()}
Dirección Máxima         : {program.getMaxAddress()}
================================================================
    """
)

# Importar módulos
import ida_name
from ida_name import set_name, get_name, SN_NOCHECK


class TestSetName:
    def __init__(self):
        self.program = currentProgram
        self.symbol_table = self.program.getSymbolTable()
        self.address_factory = self.program.getAddressFactory()
        self.default_space = self.address_factory.getDefaultAddressSpace()
        self.min_addr = self.program.getMinAddress().getOffset()
        self.max_addr = self.program.getMaxAddress().getOffset()

        print(">>> Iniciando tests para ida_name.set_name()")
        print(f"    Programa cargado       : {self.program.getName()}")
        print(f"    Rango de direcciones   : 0x{self.min_addr:x} - 0x{self.max_addr:x}")
        print("----------------------------------------------------------------")

    def get_test_address(self, offset=0x100):
        """Obtiene una dirección válida para testing (dentro del rango)."""
        addr = self.min_addr + offset
        if addr > self.max_addr:
            addr = self.min_addr  # fallback seguro
        return addr

    def test_import(self):
        """Verifica que el módulo se importe correctamente."""
        print("\n[TEST] Importación del módulo")
        print("----------------------------------------------------------------")
        assert callable(set_name), "Error: set_name no es callable"
        assert callable(get_name), "Error: get_name no es callable"
        print("Resultado: Importación correcta y funciones disponibles")

    def test_basic_symbol_creation(self):
        """Crea, verifica y borra un símbolo básico."""
        print("\n[TEST] Creación básica de símbolo")
        print("----------------------------------------------------------------")
        addr = self.get_test_address()

        print(f"Dirección seleccionada para prueba: 0x{addr:x}")

        try:
            result = set_name(addr, "test_symbol", SN_NOCHECK)
            if result != 1:
                print("Error: No se pudo crear el símbolo (resultado != 1)")
                return
            print(f"Símbolo creado correctamente en 0x{addr:x}")

            name = get_name(addr, 0)
            if "test_symbol" not in name:
                print(f"Error: El nombre obtenido no coincide (obtenido: {name})")
                return
            print(f"Verificación exitosa: nombre leído = {name}")

            result = set_name(addr, "", 0)
            if result != 1:
                print("Error: No se pudo borrar el símbolo")
                return
            print("Símbolo borrado correctamente")
        except Exception as e:
            print(f"Excepción durante el test: {e}")

    def run(self):
        """Ejecuta la suite de tests."""
        print("\n================= INICIO DE TESTS =================")
        self.test_import()
        self.test_basic_symbol_creation()
        print("\n================= FIN DE TESTS ====================")


# ================================
# Ejecución
# ================================
if __name__ == "__main__":
    tester = TestSetName()
    tester.run()
