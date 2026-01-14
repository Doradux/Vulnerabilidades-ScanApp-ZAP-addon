# 🛡️ AI Vulnerability Scanner (ZAP Wrapper)

> **Un escáner de vulnerabilidades inteligente que combina la potencia de OWASP ZAP con el análisis avanzado de Google Gemini 2.0 Flash.**

Este proyecto actúa como una capa de orquestación y análisis (Wrapper) sobre OWASP ZAP, automatizando el escaneo de seguridad y enriqueciendo los resultados con Inteligencia Artificial para reducir falsos positivos, explicar el impacto en español y generar pruebas de concepto (PoC).

---

## Características Clave

- **Automatización de ZAP**: Arranca ZAP automáticamente en modo "daemon" (segundo plano), gestionando puertos y procesos sin intervención del usuario.
- **Análisis con IA (Gemini 2.0)**:
  - No solo lista vulnerabilidades, las **entiende**.
  - Explica el riesgo y las consecuencias en lenguaje natural (Español).
  - Genera **Correcciones de Código** (Fix Code) específicas para tu tecnología.
  - Intenta generar **Exploits/PoC** (cURL) para verificar la falla.
- **Detección de Stack**: Identifica automáticamente si la web usa Laravel, WordPress, React, etc., para adaptar los consejos de seguridad.
- **Dashboard Moderno**: Reporte HTML interactivo, limpio y profesional con estadísticas y modo oscuro/claro.
- **Escaneo Híbrido (SAST + DAST)**: Combina el escaneo web (DAST) con el análisis de código fuente local (SAST) para una visión 360º.

---

## Requisitos Previos

- **Windows 10/11** (Probado en Windows)
- **Java 17+** (Necesario para ZAP)
- **Python 3.10+**

## Instalación Rápida

1.  **Clonar el repositorio:**

    ```powershell
    git clone <URL_DEL_REPO>
    cd ScanApp
    ```

2.  **Instalación Automática:**
    Ejecuta el script incluido `install.bat`.

    - Instalará las dependencias de Python (`requirements.txt`).
    - Descargará e instalará **OWASP ZAP** si no lo tienes.

3.  **Ejecutar:**
    Doble clic en `run.bat` (o ejecuta `python main.py`).

---

## Uso

1.  **Configuración del Objetivo**: Introduce la URL de la web a escanear (ej: `http://localhost`).
2.  **API Key de IA**: Pega tu clave de Google Gemini (puedes obtenerla gratis en AI Studio).
3.  **Modos de Escaneo**:
    - **Analizar Ahora**: Hace un escaneo completo (Spider + Active Scan + Análisis IA).
    - **Solo IA**: Si ya tienes un reporte previo, lo vuelve a pasar por la IA para mejorar las explicaciones.
4.  **Ver Reporte**: Al finalizar, se abrirá un Dashboard HTML con todos los hallazgos.

---

## Estructura del Proyecto

- `main.py`: **Núcleo de la aplicación**. GUI (CustomTkinter), control de hilos y orquestación de ZAP `subprocess`.
- `ai_analyzer.py`: **Ccerebro**. Conecta con la API de Gemini, procesa los JSON de ZAP, divide el trabajo en lotes (batching) y genera el HTML final.
- `db_manager.py`: Gestión de historial local (SQLite).
- `install.bat`: Script de "Setup" para despliegue rápido en máquinas nuevas.

---

## Disclaimer

Esta herramienta está diseñada para **uso ético** en aplicaciones propias o con autorización explícita. El autor no se hace responsable del mal uso de la misma.

---

_Desarrollado como Addon/Wrapper de Seguridad Ofensiva Automatizada._
