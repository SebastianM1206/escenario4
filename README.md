# Escenario 4 - Análisis de Seguridad con Python / SebastianMedinaGarcia

## 📋 Descripción

Este proyecto implementa el **Escenario 4** de análisis de vulnerabilidades usando Python. Se trabaja con una aplicación propia en Python y se utiliza **Bandit** (librería de análisis estático de seguridad) ejecutada directamente desde el código.
El proyecto permite:

- ✅ Análisis automático de vulnerabilidades en código Python
- ✅ Iteración rápida: correr → arreglar → volver a correr
- ✅ Comparación entre versión vulnerable y segura
- ✅ Generación de reportes detallados en JSON y HTML

## 🏗️ Estructura del Proyecto

```
escenario4/
├── app_vulnerable.py              # Aplicación Flask con vulnerabilidades
├── app_segura.py                  # Versión corregida de la aplicación
├── analisis_seguridad.py          # Script de análisis con Bandit
├── requirements.txt               # Dependencias del proyecto
└── README.md                      # Este archivo
```
