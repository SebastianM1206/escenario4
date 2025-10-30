#!/usr/bin/env python3
"""
Script de Prueba de Vulnerabilidades
SOLO PARA TESTING LOCAL EN app_vulnerable.py y app_segura.py
"""
import requests
import sys
from urllib.parse import quote

BASE_URL = "http://localhost:5000"


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")


def print_test(name):
    print(f"{Colors.BOLD}[TEST]{Colors.RESET} {name}")


def print_vulnerable(payload):
    print(f"  {Colors.RED}✗ VULNERABLE{Colors.RESET} a: {payload}")


def print_protected(payload):
    print(f"  {Colors.GREEN}✓ PROTEGIDO{Colors.RESET} contra: {payload}")


def print_error(msg):
    print(f"  {Colors.YELLOW}! Error:{Colors.RESET} {msg}")


def check_server():
    """Verifica si el servidor está corriendo"""
    try:
        r = requests.get(BASE_URL, timeout=2)
        return r.status_code == 200
    except:
        return False


def test_sql_injection():
    """Prueba SQL Injection en /search"""
    print_test("SQL Injection")

    payloads = [
        ("Simple OR", "%' OR '1'='1"),
        ("Comment", "admin'--"),
        ("UNION", "' UNION SELECT 1,2,3--")
    ]

    for name, payload in payloads:
        try:
            r = requests.get(
                f"{BASE_URL}/search?q={quote(payload)}", timeout=5)
            # Si vemos múltiples usuarios o todos los datos, es vulnerable
            if r.status_code == 200 and ("(1," in r.text or "(2," in r.text):
                print_vulnerable(f"{name}: {payload}")
            else:
                print_protected(f"{name}: {payload}")
        except Exception as e:
            print_error(str(e))


def test_command_injection():
    """Prueba Command Injection en /execute"""
    print_test("Command Injection")

    # Windows
    payloads_win = [
        ("Echo + Dir", "echo test && dir"),
        ("Multiple commands", "whoami & hostname"),
    ]

    # Linux
    payloads_linux = [
        ("Echo + ls", "echo test; ls"),
        ("Pipe", "echo test | cat"),
    ]

    # Probar payloads
    for name, payload in payloads_win + payloads_linux:
        try:
            r = requests.get(
                f"{BASE_URL}/execute?cmd={quote(payload)}", timeout=5)
            # Si ejecuta múltiples comandos, es vulnerable
            if r.status_code == 200 and ("test" in r.text.lower() or "volume" in r.text.lower()):
                print_vulnerable(f"{name}: {payload}")
            elif "no permitido" in r.text.lower() or "not allowed" in r.text.lower():
                print_protected(f"{name}: {payload}")
            else:
                print_protected(f"{name}: {payload}")
        except Exception as e:
            print_error(str(e))


def test_ssti():
    """Prueba Server-Side Template Injection en /template"""
    print_test("Server-Side Template Injection (SSTI)")

    payloads = [
        ("Math eval", "{{7*7}}", "49"),
        ("Config access", "{{config}}", "Config"),
        ("Class access", "{{''.__class__}}", "class")
    ]

    for name, payload, indicator in payloads:
        try:
            r = requests.get(
                f"{BASE_URL}/template?name={quote(payload)}", timeout=5)
            if r.status_code == 200 and indicator in r.text:
                print_vulnerable(f"{name}: {payload}")
            else:
                print_protected(f"{name}: {payload}")
        except Exception as e:
            print_error(str(e))


def test_yaml_injection():
    """Prueba YAML Injection en /yaml"""
    print_test("YAML Injection")

    # Payload seguro de prueba
    safe_payload = "name: John\nage: 30"

    # Payload malicioso (no lo ejecutaremos realmente, solo verificamos el parsing)
    malicious_payload = "!!python/object/apply:os.system\nargs: ['whoami']"

    try:
        # Probar payload seguro
        r = requests.post(f"{BASE_URL}/yaml",
                          data={'yaml': safe_payload}, timeout=5)
        if r.status_code == 200:
            print(f"  ℹ️  Endpoint /yaml está activo")

            # Verificar si usa Loader vulnerable o SafeLoader
            # SafeLoader rechazará !!python/object
            r2 = requests.post(f"{BASE_URL}/yaml",
                               data={'yaml': malicious_payload}, timeout=5)
            if "Error" in r2.text or "could not determine" in r2.text.lower():
                print_protected("YAML con SafeLoader")
            else:
                print_vulnerable("YAML con Loader inseguro")
    except Exception as e:
        print_error(str(e))


def test_deserialization():
    """Prueba Insecure Deserialization en /upload"""
    print_test("Insecure Deserialization")

    # Payload JSON seguro
    json_payload = '{"name": "John", "age": 30}'

    # Payload Pickle (representación hex de un dict simple)
    import pickle
    simple_dict = {"test": "data"}
    pickle_hex = pickle.dumps(simple_dict).hex()

    try:
        # Intentar con JSON
        r = requests.post(f"{BASE_URL}/upload",
                          data={'data': json_payload}, timeout=5)
        if r.status_code == 200 and "John" in r.text:
            print_protected("Usa JSON (seguro)")
        else:
            # Intentar con Pickle
            r2 = requests.post(f"{BASE_URL}/upload",
                               data={'data': pickle_hex}, timeout=5)
            if r2.status_code == 200 and "test" in r2.text:
                print_vulnerable("Usa Pickle (inseguro)")
    except Exception as e:
        print_error(str(e))


def test_information_disclosure():
    """Prueba Information Disclosure"""
    print_test("Information Disclosure")

    try:
        # Provocar un error para ver si debug está habilitado
        r = requests.get(f"{BASE_URL}/search?q='", timeout=5)

        # Si vemos stack trace detallado, debug está habilitado
        if "Traceback" in r.text or "line " in r.text:
            print_vulnerable("Debug mode habilitado (muestra stack traces)")
        else:
            print_protected("Debug mode deshabilitado o manejado")

    except Exception as e:
        print_error(str(e))


def run_all_tests():
    """Ejecuta todas las pruebas"""
    print_header("🔍 PRUEBA DE VULNERABILIDADES")

    print(f"{Colors.YELLOW}⚠️  Este script solo debe usarse en ambiente local{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Asegúrate de que la app esté corriendo en {BASE_URL}{Colors.RESET}")

    # Verificar servidor
    print("\nVerificando servidor...")
    if not check_server():
        print(f"{Colors.RED}❌ Servidor no disponible en {BASE_URL}{Colors.RESET}")
        print(
            f"{Colors.YELLOW}Inicia la aplicación con: python app_vulnerable.py{Colors.RESET}")
        sys.exit(1)

    print(f"{Colors.GREEN}✓ Servidor activo{Colors.RESET}")

    # Ejecutar pruebas
    test_sql_injection()
    test_command_injection()
    test_ssti()
    test_yaml_injection()
    test_deserialization()
    test_information_disclosure()

    print_header("✅ PRUEBAS COMPLETADAS")
    print("\nInterpretación de resultados:")
    print(f"{Colors.RED}✗ VULNERABLE{Colors.RESET} = La aplicación es susceptible al ataque")
    print(f"{Colors.GREEN}✓ PROTEGIDO{Colors.RESET} = La aplicación rechaza el ataque")
    print(f"\n{Colors.BOLD}Recomendación:{Colors.RESET}")
    print("1. Ejecuta estas pruebas en app_vulnerable.py (deberías ver vulnerabilidades)")
    print("2. Ejecuta estas pruebas en app_segura.py (deberías ver protecciones)")
    print("3. Compara los resultados para entender las correcciones\n")


if __name__ == '__main__':
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print(
            f"\n\n{Colors.YELLOW}Pruebas interrumpidas por el usuario{Colors.RESET}")
        sys.exit(0)
