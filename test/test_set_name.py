# -*- coding: utf-8 -*-
# test/test_set_name.py
# @category GCL
# @runtime PyGhidra

"""
Test suite for set_name() function in Ghidralation
Ejecutar este script desde Ghidra con un binario cargado
"""

import sys
import os

# Agregar src/ al path para importar módulos
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), "src")
sys.path.insert(0, src_dir)

# Configurar currentProgram
import cp

cp.currentProgram = currentProgram

# Importar módulos de Ghidralation
import ida_name
from ida_name import set_name, get_name
from ida_name import (
    SN_CHECK,
    SN_NOCHECK,
    SN_PUBLIC,
    SN_NON_PUBLIC,
    SN_WEAK,
    SN_NON_WEAK,
    SN_AUTO,
    SN_NON_AUTO,
    SN_NOLIST,
    SN_NOWARN,
    SN_LOCAL,
    SN_FORCE,
    SN_NODUMMY,
    SN_DELTAIL,
)


from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException, InvalidInputException


class TestSetName:
    def __init__(self):
        self.test_count = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.program = currentProgram
        self.symbol_table = self.program.getSymbolTable()
        self.address_factory = self.program.getAddressFactory()
        self.default_space = self.address_factory.getDefaultAddressSpace()

        # Obtener rango de direcciones válidas para testing
        self.min_addr = self.program.getMinAddress().getOffset()
        self.max_addr = self.program.getMaxAddress().getOffset()

        print(f"=== Iniciando Tests para ida_name.set_name() ===")
        print(f"Programa: {self.program.getName()}")
        print(f"Rango de direcciones: 0x{self.min_addr:x} - 0x{self.max_addr:x}")
        print(
            f"Módulo ida_name importado: {ida_name.__file__ if hasattr(ida_name, '__file__') else 'OK'}"
        )
        print()

    def assert_equal(self, actual, expected, test_name):
        """Verificar que dos valores sean iguales"""
        self.test_count += 1
        if actual == expected:
            print(f"✓ PASS: {test_name}")
            self.passed_tests += 1
            return True
        else:
            print(f"✗ FAIL: {test_name}")
            print(f"  Expected: {expected}")
            print(f"  Actual: {actual}")
            self.failed_tests += 1
            return False

    def assert_true(self, condition, test_name):
        """Verificar que una condición sea verdadera"""
        return self.assert_equal(condition, True, test_name)

    def assert_false(self, condition, test_name):
        """Verificar que una condición sea falsa"""
        return self.assert_equal(condition, False, test_name)

    def get_test_address(self, offset=0):
        """Obtener una dirección válida para testing"""
        test_addr = self.min_addr + offset
        if test_addr > self.max_addr:
            test_addr = self.min_addr + (offset % 0x1000)
        return test_addr

    def cleanup_test_symbols(self, addresses):
        """Limpiar símbolos de test creados"""
        for addr_offset in addresses:
            try:
                addr = self.default_space.getAddress(addr_offset)
                symbols = self.symbol_table.getSymbols(addr)
                for symbol in symbols:
                    if symbol.getName().startswith("test_"):
                        self.symbol_table.removeSymbolSpecial(symbol)
            except:
                pass

    def test_module_import(self):
        """Test de importación del módulo"""
        print("--- Test: Importación del Módulo ---")

        # Verificar que las funciones están disponibles
        self.assert_true(callable(set_name), "set_name es función")
        self.assert_true(callable(get_name), "get_name es función")

        # Verificar constantes
        self.assert_equal(SN_CHECK, 0x00, "Constante SN_CHECK")
        self.assert_equal(SN_NOCHECK, 0x01, "Constante SN_NOCHECK")
        self.assert_equal(SN_PUBLIC, 0x02, "Constante SN_PUBLIC")
        self.assert_equal(SN_FORCE, 0x800, "Constante SN_FORCE")

        print(f"  Funciones disponibles en ida_name: {dir(ida_name)}")

    def test_basic_functionality(self):
        """Test básico de funcionalidad"""
        print("\n--- Test: Funcionalidad Básica ---")

        test_addr = self.get_test_address(0x100)

        # Test 1: Crear símbolo básico
        result = set_name(test_addr, "test_basic_symbol", SN_NOCHECK)
        self.assert_equal(result, 1, "Crear símbolo básico")

        # Test 2: Verificar que se creó
        name = get_name(test_addr, 0)
        self.assert_true(
            "test_basic_symbol" in name,
            f"Verificar símbolo creado - obtenido: '{name}'",
        )

        # Test 3: Cambiar nombre existente
        result = set_name(test_addr, "test_renamed_symbol", SN_NOCHECK)
        self.assert_equal(result, 1, "Cambiar nombre existente")

        name = get_name(test_addr, 0)
        self.assert_true(
            "test_renamed_symbol" in name,
            f"Verificar cambio de nombre - obtenido: '{name}'",
        )

        # Test 4: Borrar símbolo
        result = set_name(test_addr, "", 0)
        self.assert_equal(result, 1, "Borrar símbolo")

        # Cleanup
        self.cleanup_test_symbols([test_addr])

    def test_name_validation(self):
        """Test de validación de nombres"""
        print("\n--- Test: Validación de Nombres ---")

        test_addr = self.get_test_address(0x200)

        # Test 1: Nombre válido con SN_CHECK
        result = set_name(test_addr, "valid_name123", SN_CHECK)
        self.assert_equal(result, 1, "Nombre válido con SN_CHECK")

        # Test 2: Nombre inválido con SN_CHECK (debería fallar)
        result = set_name(test_addr, "invalid-name!", SN_CHECK | SN_NOWARN)
        self.assert_equal(result, 0, "Nombre inválido con SN_CHECK debe fallar")

        # Test 3: Nombre inválido con SN_NOCHECK (debería corregir)
        result = set_name(test_addr, "invalid-name!", SN_NOCHECK)
        self.assert_equal(result, 1, "Nombre inválido con SN_NOCHECK debe corregir")

        name = get_name(test_addr, 0)
        self.assert_true(
            "invalid" in name and "_" in name,
            f"Caracteres inválidos reemplazados - obtenido: '{name}'",
        )

        # Test 4: Nombre que comienza con número
        result = set_name(test_addr, "123invalid", SN_NOCHECK)
        self.assert_equal(result, 1, "Nombre que comienza con número corregido")

        name = get_name(test_addr, 0)
        self.assert_true(
            name.startswith("_"),
            f"Prefijo añadido a nombre que comienza con número - obtenido: '{name}'",
        )

        # Cleanup
        self.cleanup_test_symbols([test_addr])

    def test_flags_functionality(self):
        """Test de funcionalidad de flags"""
        print("\n--- Test: Funcionalidad de Flags ---")

        test_addr = self.get_test_address(0x300)

        # Test 1: SN_FORCE con nombre duplicado
        result1 = set_name(test_addr, "test_duplicate", SN_NOCHECK)
        self.assert_equal(result1, 1, "Crear primer símbolo duplicado")

        result2 = set_name(test_addr + 4, "test_duplicate", SN_FORCE | SN_NOCHECK)
        self.assert_equal(result2, 1, "SN_FORCE debe crear variación de nombre")

        name2 = get_name(test_addr + 4, 0)
        # Puede ser test_duplicate_1, test_duplicate_2, etc.
        self.assert_true(
            "test_duplicate" in name2,
            f"Verificar nombre con variación - obtenido: '{name2}'",
        )

        # Test 2: SN_NODUMMY
        result = set_name(test_addr + 8, "sub_test_function", SN_NODUMMY | SN_NOCHECK)
        self.assert_equal(result, 1, "SN_NODUMMY aplicado")

        name = get_name(test_addr + 8, 0)
        self.assert_true(
            "_sub_test_function" in name, f"Prefix dummy añadido - obtenido: '{name}'"
        )

        # Test 3: SN_AUTO vs SN_NON_AUTO
        result = set_name(test_addr + 12, "test_auto", SN_AUTO | SN_NOCHECK)
        self.assert_equal(result, 1, "SN_AUTO aplicado")

        result = set_name(test_addr + 16, "test_non_auto", SN_NON_AUTO | SN_NOCHECK)
        self.assert_equal(result, 1, "SN_NON_AUTO aplicado")

        # Cleanup
        self.cleanup_test_symbols(
            [test_addr, test_addr + 4, test_addr + 8, test_addr + 12, test_addr + 16]
        )

    def test_edge_cases(self):
        """Test de casos extremos"""
        print("\n--- Test: Casos Extremos ---")

        # Test 1: Dirección inválida
        result = set_name(0xFFFFFFFFFFFFFFFF, "test_invalid_addr", SN_NOWARN)
        self.assert_equal(result, 0, "Dirección inválida debe fallar")

        # Test 2: Nombre None
        test_addr = self.get_test_address(0x400)
        result = set_name(test_addr, None, 0)
        self.assert_equal(result, 0, "Nombre None debe retornar 0")

        # Test 3: Nombre vacío para borrar
        # Primero crear un símbolo
        set_name(test_addr, "temp_symbol", SN_NOCHECK)
        result = set_name(test_addr, "", 0)
        self.assert_equal(result, 1, "Nombre vacío debe borrar símbolo")

        # Test 4: Nombre muy largo
        long_name = "a" * 200  # Reducido para evitar problemas
        result = set_name(test_addr, long_name, SN_NOCHECK | SN_NOWARN)
        # No verificamos resultado específico, puede variar según Ghidra
        print(f"  Nombre largo (200 chars): resultado = {result}")

        # Test 5: Caracteres especiales extremos
        special_name = "test@#$%^&*(){}[]|\\:;\"'<>?/.,~`"
        result = set_name(test_addr, special_name, SN_NOCHECK)
        self.assert_equal(result, 1, "Caracteres especiales extremos con SN_NOCHECK")

        name = get_name(test_addr, 0)
        print(f"  Caracteres especiales convertidos a: '{name}'")

        # Cleanup
        self.cleanup_test_symbols([test_addr])

    def test_integration_with_existing_symbols(self):
        """Test de integración con símbolos existentes"""
        print("\n--- Test: Integración con Símbolos Existentes ---")

        # Buscar algunas funciones existentes en el programa
        function_manager = self.program.getFunctionManager()
        functions = list(function_manager.getFunctions(True))

        if not functions:
            print("  No hay funciones en el programa para testing")
            return

        tested_functions = 0
        for func in functions[:3]:  # Limitar a 3 funciones
            addr = func.getEntryPoint().getOffset()
            original_name = func.getName()

            print(f"  Testing función en 0x{addr:x}: '{original_name}'")

            # Test: Obtener nombre actual
            current_name = get_name(addr, 0)
            self.assert_true(
                len(current_name) > 0,
                f"get_name en función existente - obtenido: '{current_name}'",
            )

            # Test: Cambiar nombre temporalmente
            temp_name = f"TEMP_TEST_{original_name}"
            result = set_name(addr, temp_name, SN_NOCHECK)

            if result == 1:
                # Verificar cambio
                new_name = get_name(addr, 0)
                change_success = temp_name in new_name
                self.assert_true(
                    change_success,
                    f"Modificar función existente '{original_name}' -> '{new_name}'",
                )

                # Restaurar nombre original
                restore_result = set_name(addr, original_name, SN_NOCHECK)
                if restore_result == 1:
                    restored_name = get_name(addr, 0)
                    self.assert_true(
                        original_name in restored_name,
                        f"Restaurar nombre original '{original_name}'",
                    )
                else:
                    print(f"  ⚠ Warning: No se pudo restaurar '{original_name}'")
            else:
                print(f"  ⚠ Warning: No se pudo modificar función '{original_name}'")

            tested_functions += 1

        print(f"  Funciones probadas: {tested_functions}")

    def test_performance(self):
        """Test básico de rendimiento"""
        print("\n--- Test: Rendimiento Básico ---")

        import time

        start_addr = self.get_test_address(0x5000)
        test_count = 50  # Reducido para evitar saturar

        # Test creación masiva
        start_time = time.time()
        created = 0

        for i in range(test_count):
            addr = start_addr + (i * 4)
            if addr > self.max_addr:
                break
            result = set_name(addr, f"perf_test_symbol_{i}", SN_NOCHECK | SN_NOWARN)
            if result == 1:
                created += 1

        creation_time = time.time() - start_time

        # Test lectura masiva
        start_time = time.time()
        read_count = 0

        for i in range(created):
            addr = start_addr + (i * 4)
            name = get_name(addr, 0)
            if "perf_test_symbol" in name:
                read_count += 1

        read_time = time.time() - start_time

        print(f"  Símbolos creados: {created}/{test_count} en {creation_time:.3f}s")
        print(f"  Símbolos leídos: {read_count}/{created} en {read_time:.3f}s")
        print(f"  Velocidad creación: {created/creation_time:.1f} símbolos/s")
        print(f"  Velocidad lectura: {read_count/read_time:.1f} símbolos/s")

        # Cleanup
        cleanup_addrs = [start_addr + (i * 4) for i in range(created)]
        self.cleanup_test_symbols(cleanup_addrs)

    def run_all_tests(self):
        """Ejecutar todos los tests"""
        print("Ejecutando suite completa de tests...\n")

        try:
            self.test_module_import()
            self.test_basic_functionality()
            self.test_name_validation()
            self.test_flags_functionality()
            self.test_edge_cases()
            self.test_integration_with_existing_symbols()
            self.test_performance()

        except Exception as e:
            print(f"Error durante testing: {str(e)}")
            import traceback

            traceback.print_exc()

        finally:
            self.print_summary()

    def print_summary(self):
        """Imprimir resumen de resultados"""
        print("\n" + "=" * 60)
        print("RESUMEN DE TESTS - ida_name.set_name()")
        print("=" * 60)
        print(f"Total de tests: {self.test_count}")
        print(f"Tests pasados: {self.passed_tests}")
        print(f"Tests fallidos: {self.failed_tests}")

        if self.failed_tests == 0:
            print("✓ TODOS LOS TESTS PASARON!")
        else:
            success_rate = (self.passed_tests / self.test_count) * 100
            print(f"Tasa de éxito: {success_rate:.1f}%")
            print("\nRevisa los tests fallidos para depurar problemas.")

        print(f"\nMódulo probado: ida_name")
        print(f"Programa de test: {self.program.getName()}")
        print("=" * 60)


# Script principal para ejecutar tests
def run_tests():
    """Función principal para ejecutar los tests"""
    if currentProgram is None:
        print("❌ Error: No hay programa cargado en Ghidra")
        print("Por favor carga un binario antes de ejecutar los tests")
        return

    try:
        tester = TestSetName()
        tester.run_all_tests()
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        print("Verifica que el módulo ida_name esté en la ruta correcta")
        print(f"Ruta buscada: {src_dir}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        import traceback

        traceback.print_exc()


def quick_test():
    """Test rápido para verificación básica"""
    print("=== Test Rápido de ida_name ===")

    try:
        # Verificar importación
        print("Importando ida_name...")
        from ida_name import set_name, get_name, SN_NOCHECK

        print("✓ Importación exitosa")

        # Obtener una dirección válida
        min_addr = currentProgram.getMinAddress().getOffset()
        test_addr = min_addr + 0x100

        print(f"Testing en dirección: 0x{test_addr:x}")

        # Test básico
        result = set_name(test_addr, "quick_test_symbol", SN_NOCHECK)
        print(f"set_name result: {result}")

        name = get_name(test_addr, 0)
        print(f"get_name result: '{name}'")

        # Verificar
        if result == 1 and "quick_test_symbol" in name:
            print("✓ Test básico PASÓ")
        else:
            print("✗ Test básico FALLÓ")

        # Limpiar
        set_name(test_addr, "", 0)
        print("✓ Cleanup completado")

    except Exception as e:
        print(f"❌ Error en quick test: {e}")
        import traceback

        traceback.print_exc()


def test_specific_flags():
    """Test específico para verificar flags individuales"""
    print("=== Test Específico de Flags ===")

    try:
        from ida_name import (
            set_name,
            get_name,
            SN_CHECK,
            SN_NOCHECK,
            SN_FORCE,
            SN_NODUMMY,
        )

        min_addr = currentProgram.getMinAddress().getOffset()
        base_addr = min_addr + 0x2000

        tests = [
            (base_addr, "valid_name", SN_CHECK, "SN_CHECK con nombre válido"),
            (
                base_addr + 4,
                "invalid-name!",
                SN_NOCHECK,
                "SN_NOCHECK con caracteres inválidos",
            ),
            (base_addr + 8, "sub_function", SN_NODUMMY | SN_NOCHECK, "SN_NODUMMY"),
            (base_addr + 12, "duplicate", SN_NOCHECK, "Primer duplicado"),
            (
                base_addr + 16,
                "duplicate",
                SN_FORCE | SN_NOCHECK,
                "SN_FORCE con duplicado",
            ),
        ]

        for addr, name, flags, description in tests:
            print(f"\nTest: {description}")
            print(f"  Dirección: 0x{addr:x}, Nombre: '{name}', Flags: 0x{flags:x}")

            result = set_name(addr, name, flags)
            actual_name = get_name(addr, 0)

            print(f"  Resultado: {result}, Nombre obtenido: '{actual_name}'")

            # Cleanup
            set_name(addr, "", 0)

        print("\n✓ Test de flags completado")

    except Exception as e:
        print(f"❌ Error en test de flags: {e}")


# Para ejecutar desde Ghidra Script Manager:
if __name__ == "__main__":
    print(
        """
╔══════════════════════════════════════════════════════════════╗
║                    TEST SUITE - ida_name                     ║
║                                                              ║
║  Para ejecutar los tests, usa una de estas funciones:        ║
║                                                              ║
║  run_tests()           # Suite completa de tests             ║
║  quick_test()          # Test rápido básico                  ║
║  test_specific_flags() # Test específico de flags            ║
║                                                              ║
║  Asegúrate de tener un programa cargado en Ghidra            ║
╚══════════════════════════════════════════════════════════════╝
    """
    )

    # Ejecutar test por defecto
    run_tests()
