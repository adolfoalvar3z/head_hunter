# Auditoría de Cabeceras

Este script está diseñado para auditar las cabeceras HTTP de un conjunto de URLs. La auditoría incluye la verificación de cabeceras de seguridad y otras configuraciones importantes para asegurar que las aplicaciones web cumplan con las mejores prácticas de seguridad.

## Características

- Verificación de cabeceras de seguridad como `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, entre otras.
- Generación de un reporte detallado con los resultados de la auditoría.
- Soporte para múltiples URLs.

## Instalación

1. Clona este repositorio:
    ```bash
    git clone https://github.com/adolfoalvar3z/head_hunter.git
    ```
2. Navega al directorio del proyecto:
    ```bash
    cd cabeceras
    ```
3. Instala las dependencias necesarias:
    ```bash
    pip install -r requirements.txt
    ```

## Uso

Para ejecutar el script, utiliza el siguiente comando:
```bash
python header_hunter.py
```
posteriormente ingresa la URL a revisar
