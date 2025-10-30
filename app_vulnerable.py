"""
Aplicación Web Vulnerable - Escenario 4
Esta aplicación contiene vulnerabilidades intencionadas para propósitos educativos
"""
import os
import pickle
import subprocess
import sqlite3
from flask import Flask, request, render_template_string, redirect, session
from markupsafe import escape
import yaml

app = Flask(__name__)

# VULNERABILIDAD 1: Hardcoded Secret Key
app.secret_key = 'mi_clave_super_secreta_12345'

# VULNERABILIDAD 2: Hardcoded Password
DATABASE_PASSWORD = 'admin123'
API_KEY = 'sk-1234567890abcdef'

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
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')")
    cursor.execute("INSERT INTO users VALUES (2, 'user', 'user123', 'user@example.com')")
    conn.commit()
    return conn

conn = init_db()

@app.route('/')
def index():
    html = '''
    <html>
        <head><title>Aplicación Vulnerable - Escenario 4</title></head>
        <body>
            <h1>Bienvenido a la Aplicación Vulnerable</h1>
            <ul>
                <li><a href="/search">Buscar Usuario (SQL Injection)</a></li>
                <li><a href="/execute">Ejecutar Comando (Command Injection)</a></li>
                <li><a href="/upload">Subir Archivo (Insecure Deserialization)</a></li>
                <li><a href="/template">Template Injection</a></li>
                <li><a href="/yaml">YAML Parser</a></li>
            </ul>
        </body>
    </html>
    '''
    return html

# VULNERABILIDAD 3: SQL Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        cursor = conn.cursor()
        # SQL Injection vulnerable
        sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            return f"<h2>Resultados:</h2><pre>{results}</pre><br><a href='/'>Volver</a>"
        except Exception as e:
            return f"<h2>Error:</h2><pre>{str(e)}</pre><br><a href='/'>Volver</a>"
    
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

# VULNERABILIDAD 4: Command Injection
@app.route('/execute')
def execute():
    cmd = request.args.get('cmd', '')
    if cmd:
        # Command Injection vulnerable
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return f"<h2>Resultado:</h2><pre>{output.decode()}</pre><br><a href='/'>Volver</a>"
        except Exception as e:
            return f"<h2>Error:</h2><pre>{str(e)}</pre><br><a href='/'>Volver</a>"
    
    return '''
    <html>
        <body>
            <h2>Ejecutar Comando</h2>
            <form action="/execute" method="get">
                <input type="text" name="cmd" placeholder="echo Hello">
                <button type="submit">Ejecutar</button>
            </form>
            <br><a href="/">Volver</a>
            <p><small>Ejemplo: echo Hello World</small></p>
        </body>
    </html>
    '''

# VULNERABILIDAD 5: Insecure Deserialization (Pickle)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        data = request.form.get('data', '')
        if data:
            try:
                # Pickle deserialization vulnerable
                obj = pickle.loads(bytes.fromhex(data))
                return f"<h2>Objeto deserializado:</h2><pre>{obj}</pre><br><a href='/'>Volver</a>"
            except Exception as e:
                return f"<h2>Error:</h2><pre>{str(e)}</pre><br><a href='/'>Volver</a>"
    
    return '''
    <html>
        <body>
            <h2>Deserializar Objeto</h2>
            <form action="/upload" method="post">
                <input type="text" name="data" placeholder="Datos en hexadecimal">
                <button type="submit">Deserializar</button>
            </form>
            <br><a href="/">Volver</a>
        </body>
    </html>
    '''

# VULNERABILIDAD 6: Server Side Template Injection (SSTI)
@app.route('/template')
def template():
    name = request.args.get('name', 'Visitante')
    # Template Injection vulnerable
    template = f"<html><body><h2>Hola {name}!</h2><br><a href='/'>Volver</a></body></html>"
    return render_template_string(template)

# VULNERABILIDAD 7: YAML Deserialization
@app.route('/yaml', methods=['GET', 'POST'])
def yaml_parser():
    if request.method == 'POST':
        yaml_data = request.form.get('yaml', '')
        if yaml_data:
            try:
                # YAML unsafe load
                data = yaml.load(yaml_data, Loader=yaml.Loader)
                return f"<h2>Datos parseados:</h2><pre>{data}</pre><br><a href='/'>Volver</a>"
            except Exception as e:
                return f"<h2>Error:</h2><pre>{str(e)}</pre><br><a href='/'>Volver</a>"
    
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

# VULNERABILIDAD 8: Uso de assert (no debe usarse en producción)
def validate_user(username):
    assert username != "", "Username cannot be empty"
    return True

# VULNERABILIDAD 9: Try-except con pass (oculta errores)
@app.route('/debug')
def debug():
    try:
        # Código que puede fallar
        result = 1 / 0
    except:
        pass
    return "Debug page"

if __name__ == '__main__':
    # VULNERABILIDAD 10: Debug mode en producción
    app.run(debug=True, host='0.0.0.0', port=5000)

