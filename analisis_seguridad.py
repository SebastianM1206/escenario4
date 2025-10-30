"""
Script de Análisis de Seguridad - Escenario 4
Utiliza Bandit para análisis estático de vulnerabilidades en código Python
"""
import subprocess
import json
import os
from datetime import datetime
import sys


class AnalizadorSeguridad:
    def __init__(self):
        self.resultados = {
            'app_vulnerable': None,
            'app_segura': None,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def analizar_archivo(self, archivo):
        """
        Analiza un archivo Python con Bandit
        """
        print(f"\n{'='*80}")
        print(f"Analizando: {archivo}")
        print(f"{'='*80}\n")

        try:
            # Verificar que el archivo existe
            if not os.path.exists(archivo):
                print(f"❌ Error: El archivo {archivo} no existe")
                return None

            # Ejecutar Bandit con formato JSON como módulo de Python
            cmd = [
                sys.executable,
                '-m', 'bandit',
                '-f', 'json',
                '-o', f'{archivo}_bandit_report.json',
                archivo
            ]

            resultado = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            # Verificar si hubo un error al ejecutar
            if resultado.returncode == 1:
                # Código 1 de Bandit significa que encontró problemas (es normal)
                pass
            elif "No module named" in resultado.stderr or "No module named" in resultado.stdout:
                print("❌ Error: Bandit no está instalado.")
                print("Instala las dependencias con: pip install -r requirements.txt")
                sys.exit(1)

            # Leer el reporte JSON
            if not os.path.exists(f'{archivo}_bandit_report.json'):
                print(f"❌ Error: No se pudo generar el reporte para {archivo}")
                print(f"Salida del comando: {resultado.stdout}")
                print(f"Errores: {resultado.stderr}")
                return None

            with open(f'{archivo}_bandit_report.json', 'r', encoding='utf-8') as f:
                reporte = json.load(f)

            # Mostrar resumen en consola
            self.mostrar_resumen(reporte, archivo)

            return reporte

        except Exception as e:
            print(f"❌ Error al analizar {archivo}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def mostrar_resumen(self, reporte, archivo):
        """
        Muestra un resumen de las vulnerabilidades encontradas
        """
        resultados = reporte.get('results', [])
        metricas = reporte.get('metrics', {})

        print(f"\n📊 RESUMEN DEL ANÁLISIS: {archivo}")
        print(f"{'─'*80}")

        # Estadísticas generales
        total_loc = metricas.get('_totals', {}).get('loc', 0)
        total_issues = len(resultados)

        print(f"Total de problemas encontrados: {total_issues}")

        # Clasificar por severidad
        severidades = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        confianzas = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for issue in resultados:
            sev = issue.get('issue_severity', 'UNKNOWN')
            conf = issue.get('issue_confidence', 'UNKNOWN')
            if sev in severidades:
                severidades[sev] += 1
            if conf in confianzas:
                confianzas[conf] += 1

        print(f"\nPor severidad:")
        print(f"  🔴 Alta:    {severidades['HIGH']}")
        print(f"  🟡 Media:   {severidades['MEDIUM']}")
        print(f"  🟢 Baja:    {severidades['LOW']}")

        print(f"\nPor confianza:")
        print(f"  Alta:    {confianzas['HIGH']}")
        print(f"  Media:   {confianzas['MEDIUM']}")
        print(f"  Baja:    {confianzas['LOW']}")

        # Mostrar detalles de las vulnerabilidades
        if resultados:
            print(f"\n🔍 VULNERABILIDADES DETECTADAS:")
            print(f"{'─'*80}\n")

            for i, issue in enumerate(resultados, 1):
                severidad = issue.get('issue_severity', 'UNKNOWN')
                confianza = issue.get('issue_confidence', 'UNKNOWN')
                linea = issue.get('line_number', 'N/A')
                texto = issue.get('issue_text', 'Sin descripción')
                test_id = issue.get('test_id', 'N/A')

                # Emoji según severidad
                emoji = '🔴' if severidad == 'HIGH' else '🟡' if severidad == 'MEDIUM' else '🟢'

                print(f"{emoji} Vulnerabilidad #{i}")
                print(f"   Línea: {linea}")
                print(f"   Severidad: {severidad} | Confianza: {confianza}")
                print(f"   Test ID: {test_id}")
                print(f"   Descripción: {texto}")
                print()
        else:
            print(f"\n✅ No se encontraron vulnerabilidades!")

    def comparar_resultados(self):
        """
        Compara los resultados entre app vulnerable y segura
        """
        print(f"\n{'='*80}")
        print("COMPARACIÓN: Aplicación Vulnerable vs Segura")
        print(f"{'='*80}\n")

        vuln_issues = len(self.resultados['app_vulnerable'].get('results', []))
        segura_issues = len(self.resultados['app_segura'].get('results', []))

        mejora = vuln_issues - segura_issues
        porcentaje = (mejora / vuln_issues * 100) if vuln_issues > 0 else 0

        print(f"Vulnerabilidades en app_vulnerable.py: {vuln_issues}")
        print(f"Vulnerabilidades en app_segura.py: {segura_issues}")
        print(
            f"\n✨ Mejora: {mejora} vulnerabilidades corregidas ({porcentaje:.1f}% reducción)")

        # Identificar qué vulnerabilidades fueron corregidas
        vuln_tests = set(
            issue['test_id'] for issue in self.resultados['app_vulnerable'].get('results', []))
        segura_tests = set(
            issue['test_id'] for issue in self.resultados['app_segura'].get('results', []))

        corregidas = vuln_tests - segura_tests
        persistentes = vuln_tests & segura_tests
        nuevas = segura_tests - vuln_tests

        if corregidas:
            print(f"\n✅ Tipos de vulnerabilidades corregidas:")
            for test_id in corregidas:
                print(f"   - {test_id}")

        if persistentes:
            print(f"\n⚠️  Tipos de vulnerabilidades persistentes:")
            for test_id in persistentes:
                print(f"   - {test_id}")

        if nuevas:
            print(f"\n❗ Nuevos problemas introducidos:")
            for test_id in nuevas:
                print(f"   - {test_id}")

    def generar_reporte_html(self):
        """
        Genera un reporte HTML comparativo
        """
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Análisis de Seguridad - Escenario 4</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #667eea;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }}
        .timestamp {{
            text-align: center;
            color: #999;
            font-size: 0.9em;
            margin-bottom: 40px;
        }}
        .comparison {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}
        .card {{
            background: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            border-left: 5px solid #dc3545;
        }}
        .card.secure {{
            border-left-color: #28a745;
        }}
        .card h2 {{
            margin-bottom: 15px;
            color: #333;
            font-size: 1.5em;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .severity {{
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }}
        .severity-high {{ border-left: 4px solid #dc3545; }}
        .severity-medium {{ border-left: 4px solid #ffc107; }}
        .severity-low {{ border-left: 4px solid #28a745; }}
        
        .vulnerability {{
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge-high {{
            background: #dc3545;
            color: white;
        }}
        .badge-medium {{
            background: #ffc107;
            color: #333;
        }}
        .badge-low {{
            background: #28a745;
            color: white;
        }}
        .improvement {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin: 40px 0;
        }}
        .improvement h2 {{
            color: white;
            margin-bottom: 20px;
        }}
        .improvement-number {{
            font-size: 4em;
            font-weight: bold;
            margin: 20px 0;
        }}
        .corrected-list {{
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: left;
        }}
        .corrected-list h3 {{
            color: white;
            margin-bottom: 15px;
        }}
        .corrected-item {{
            background: rgba(255,255,255,0.2);
            margin: 8px 0;
            padding: 10px 15px;
            border-radius: 5px;
        }}
        @media (max-width: 768px) {{
            .comparison {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Reporte de Análisis de Seguridad</h1>
        <div class="subtitle">Escenario 4 - Análisis con Python (Bandit)</div>
        <div class="timestamp">Generado: {self.resultados['timestamp']}</div>
        """

        # Estadísticas comparativas
        vuln_results = self.resultados['app_vulnerable'].get('results', [])
        segura_results = self.resultados['app_segura'].get('results', [])

        vuln_count = len(vuln_results)
        segura_count = len(segura_results)
        mejora = vuln_count - segura_count
        porcentaje = (mejora / vuln_count * 100) if vuln_count > 0 else 0

        # Sección de mejora
        html += f"""
        <div class="improvement">
            <h2>✨ Resultados de la Corrección</h2>
            <div class="improvement-number">{mejora}</div>
            <p style="font-size: 1.2em;">Vulnerabilidades corregidas ({porcentaje:.1f}% reducción)</p>
        """

        # Listar vulnerabilidades corregidas
        vuln_tests = {issue['test_id']: issue['issue_text']
                      for issue in vuln_results}
        segura_tests = set(issue['test_id'] for issue in segura_results)
        corregidas = {k: v for k, v in vuln_tests.items()
                      if k not in segura_tests}

        if corregidas:
            html += """
            <div class="corrected-list">
                <h3>Vulnerabilidades Corregidas:</h3>
            """
            for test_id, descripcion in corregidas.items():
                html += f'<div class="corrected-item">✅ {test_id}: {descripcion}</div>'
            html += "</div>"

        html += "</div>"

        # Comparación lado a lado
        html += '<div class="comparison">'

        # Aplicación vulnerable
        html += self._generar_card_html("app_vulnerable.py", vuln_results, "")

        # Aplicación segura
        html += self._generar_card_html("app_segura.py",
                                        segura_results, "secure")

        html += "</div>"

        html += """
    </div>
</body>
</html>
        """

        with open('reporte_seguridad.html', 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"\n✅ Reporte HTML generado: reporte_seguridad.html")

    def _generar_card_html(self, nombre, resultados, clase_extra=""):
        """
        Genera HTML para una tarjeta de aplicación
        """
        # Contar por severidad
        severidades = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in resultados:
            sev = issue.get('issue_severity', 'UNKNOWN')
            if sev in severidades:
                severidades[sev] += 1

        html = f'<div class="card {clase_extra}">'
        html += f'<h2>{"🔴" if not clase_extra else "🟢"} {nombre}</h2>'

        html += '<div class="stats">'
        html += '<div class="stat">'
        html += f'<div class="stat-number">{len(resultados)}</div>'
        html += '<div class="stat-label">Total Issues</div>'
        html += '</div>'
        html += '</div>'

        html += '<div class="severity severity-high">'
        html += f'<span>Alta</span><strong>{severidades["HIGH"]}</strong>'
        html += '</div>'

        html += '<div class="severity severity-medium">'
        html += f'<span>Media</span><strong>{severidades["MEDIUM"]}</strong>'
        html += '</div>'

        html += '<div class="severity severity-low">'
        html += f'<span>Baja</span><strong>{severidades["LOW"]}</strong>'
        html += '</div>'

        # Listar vulnerabilidades
        if resultados:
            for issue in resultados[:5]:  # Mostrar solo las primeras 5
                sev = issue.get('issue_severity', 'UNKNOWN').lower()
                linea = issue.get('line_number', 'N/A')
                texto = issue.get('issue_text', 'Sin descripción')

                html += f'<div class="vulnerability">'
                html += f'<div class="vuln-header">'
                html += f'<span>Línea {linea}</span>'
                html += f'<span class="badge badge-{sev}">{issue.get("issue_severity", "UNKNOWN")}</span>'
                html += f'</div>'
                html += f'<div>{texto}</div>'
                html += f'</div>'

        html += '</div>'
        return html

    def ejecutar_analisis_completo(self):
        """
        Ejecuta el análisis completo de ambas aplicaciones
        """
        print("\n" + "="*80)
        print("🔍 ANÁLISIS DE SEGURIDAD - ESCENARIO 4")
        print("="*80)

        # Analizar aplicación vulnerable
        self.resultados['app_vulnerable'] = self.analizar_archivo(
            'app_vulnerable.py')

        # Analizar aplicación segura
        self.resultados['app_segura'] = self.analizar_archivo('app_segura.py')

        # Comparar resultados
        if self.resultados['app_vulnerable'] and self.resultados['app_segura']:
            self.comparar_resultados()
            self.generar_reporte_html()

        print("\n" + "="*80)
        print("✅ ANÁLISIS COMPLETADO")
        print("="*80)
        print("\nArchivos generados:")
        print("  📄 app_vulnerable.py_bandit_report.json")
        print("  📄 app_segura.py_bandit_report.json")
        print("  🌐 reporte_seguridad.html")
        print("\nAbre reporte_seguridad.html en tu navegador para ver el reporte completo.")


def main():
    analizador = AnalizadorSeguridad()
    analizador.ejecutar_analisis_completo()


if __name__ == '__main__':
    main()
