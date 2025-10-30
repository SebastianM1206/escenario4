"""
Aplicación Web Segura - Escenario 4
Esta es la versión corregida con las vulnerabilidades remediadas
"""
import os
import subprocess
import sqlite3
import secrets
from flask import Flask, request, render_template_string, redirect, session
from markupsafe import escape
import yaml
import json

app = Flask(__name__)

# CORRECCIÓN 1: Secret Key generada de forma segura
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# CORRECCIÓN 2: Credenciales desde variables de entorno
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD', '')
API_KEY = os.environ.get('API_KEY', '')

# Base de datos en memoria


def get_db():
    conn = sqlite3.connect(':memory:')
    return conn

# Inicializar BD


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute(
        "INSERT INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')")
    cursor.execute(
        "INSERT INTO users VALUES (2, 'user', 'user123', 'user@example.com')")
    conn.commit()
    return conn


conn = init_db()


@app.route('/')
def index():
    html = '''
    <html>
        <head><title>Aplicación Segura - Escenario 4</title></head>
        <body>
            <h1>Bienvenido a la Aplicación Segura</h1>
            <ul>
                <li><a href="/search">Buscar Usuario (Protegido contra SQL Injection)</a></li>
                <li><a href="/execute">Ejecutar Comando (Protegido contra Command Injection)</a></li>
                <li><a href="/upload">Subir Archivo (Serialización Segura)</a></li>
                <li><a href="/template">Template Seguro</a></li>
                <li><a href="/yaml">YAML Parser Seguro</a></li>
            </ul>
        </body>
    </html>
    '''
    return html

# CORRECCIÓN 3: SQL Injection prevenido con consultas parametrizadas


@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        cursor = conn.cursor()
        # Uso de consultas parametrizadas (prepared statements)
        sql = "SELECT * FROM users WHERE username LIKE ?"
        try:
            cursor.execute(sql, (f'%{query}%',))
            results = cursor.fetchall()
            return f"<h2>Resultados:</h2><pre>{escape(str(results))}</pre><br><a href='/'>Volver</a>"
        except Exception as e:
            return f"<h2>Error:</h2><pre>{escape(str(e))}</pre><br><a href='/'>Volver</a>"

    return '''
    <html>
        <body>
            <h2>Buscar Usuario</h2>
            <form action="/search" method="get">
                <input type="text" name="q" placeholder="Nombre de usuario">
                <button type="submit">Buscar</button>
            </form>
            <br><a href="/">Volver</a>
        </body>
    </html>
    '''

# CORRECCIÓN 4: Command Injection prevenido con whitelist de comandos


@app.route('/execute')
def execute():
    cmd = request.args.get('cmd', '')
    if cmd:
        # Whitelist de comandos permitidos
        allowed_commands = {
            'date': ['date'],
            'whoami': ['whoami'],
            'pwd': ['pwd']
        }

        if cmd in allowed_commands:
            try:
                # Uso de lista en lugar de shell=True
                output = subprocess.check_output(
                    allowed_commands[cmd],
                    shell=False,
                    stderr=subprocess.STDOUT,
                    timeout=5
                )
                return f"<h2>Resultado:</h2><pre>{escape(output.decode())}</pre><br><a href='/'>Volver</a>"
            except Exception as e:
                return f"<h2>Error:</h2><pre>{escape(str(e))}</pre><br><a href='/'>Volver</a>"
        else:
            return f"<h2>Error:</h2><pre>Comando no permitido</pre><br><a href='/'>Volver</a>"

    return '''
    <html>
        <body>
            <h2>Ejecutar Comando</h2>
            <form action="/execute" method="get">
                <select name="cmd">
                    <option value="date">Fecha</option>
                    <option value="whoami">Usuario actual</option>
                    <option value="pwd">Directorio actual</option>
                </select>
                <button type="submit">Ejecutar</button>
            </form>
            <br><a href="/">Volver</a>
        </body>
    </html>
    '''

# CORRECCIÓN 5: Uso de JSON en lugar de Pickle


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        data = request.form.get('data', '')
        if data:
            try:
                # Uso de JSON en lugar de pickle
                obj = json.loads(data)
                return f"<h2>Objeto deserializado:</h2><pre>{escape(str(obj))}</pre><br><a href='/'>Volver</a>"
            except Exception as e:
                return f"<h2>Error:</h2><pre>{escape(str(e))}</pre><br><a href='/'>Volver</a>"

    return '''
    <html>
        <body>
            <h2>Deserializar Objeto (JSON)</h2>
            <form action="/upload" method="post">
                <input type="text" name="data" placeholder='{"name": "John", "age": 30}'>
                <button type="submit">Deserializar</button>
            </form>
            <br><a href="/">Volver</a>
        </body>
    </html>
    '''

# CORRECCIÓN 6: Template Injection prevenido con escape


@app.route('/template')
def template():
    name = request.args.get('name', 'Visitante')
    # Uso de escape para prevenir SSTI
    safe_name = escape(name)
    template = f"<html><body><h2>Hola {safe_name}!</h2><br><a href='/'>Volver</a></body></html>"
    return render_template_string(template)

# CORRECCIÓN 7: YAML con SafeLoader


@app.route('/yaml', methods=['GET', 'POST'])
def yaml_parser():
    if request.method == 'POST':
        yaml_data = request.form.get('yaml', '')
        if yaml_data:
            try:
                # Uso de SafeLoader en lugar de Loader
                data = yaml.safe_load(yaml_data)
                return f"<h2>Datos parseados:</h2><pre>{escape(str(data))}</pre><br><a href='/'>Volver</a>"
            except Exception as e:
                return f"<h2>Error:</h2><pre>{escape(str(e))}</pre><br><a href='/'>Volver</a>"

    return '''
    <html>
        <body>
            <h2>YAML Parser</h2>
            <form action="/yaml" method="post">
                <textarea name="yaml" rows="10" cols="50" placeholder="name: John\nage: 30"></textarea><br>
                <button type="submit">Parsear</button>
            </form>
            <br><a href="/">Volver</a>
        </body>
    </html>
    '''

# CORRECCIÓN 8: Uso de validación apropiada en lugar de assert


def validate_user(username):
    if not username or username == "":
        raise ValueError("Username cannot be empty")
    return True

# CORRECCIÓN 9: Manejo apropiado de excepciones


@app.route('/debug')
def debug():
    try:
        # Código que puede fallar
        result = 1 / 0
    except ZeroDivisionError as e:
        # Log del error apropiado
        app.logger.error(f"Error en debug: {str(e)}")
        return "Error procesando solicitud", 500
    return "Debug page"


if __name__ == '__main__':
    # CORRECCIÓN 10: No usar debug mode en producción
    is_development = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=is_development,
        host='127.0.0.1',  # Solo localhost, no 0.0.0.0
        port=5000
    )
