# Auditoría de Cabeceras

Este script está diseñado para auditar las cabeceras HTTP de un conjunto de URLs. La auditoría incluye la verificación de cabeceras de seguridad y otras configuraciones importantes para asegurar que las aplicaciones web cumplan con las mejores prácticas de seguridad.

## Características

- Verificación de cabeceras de seguridad como `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, entre otras.
- Generación de un reporte detallado con los resultados de la auditoría.

## Instalación

1. Clona este repositorio:
    ```bash
    git clone https://github.com/adolfoalvar3z/head_hunter.git
    ```
2. Navega al directorio del proyecto:
    ```bash
    cd header_hunter
    ```
3. Crea y activa un entorno virtual:
    ```bash
    python -m venv venv
    source venv/bin/activate  # En Windows usa `venv\Scripts\activate`
    ```
4. Instala las dependencias necesarias:
    ```bash
    pip install -r requirements.txt
    ```

## Uso

Para ejecutar el script, utiliza el siguiente comando:
```bash
python header_hunter.py
```
posteriormente ingresa la URL a revisar.

## Descripción del Script header_hunter.py

### Importación de Módulos:

- Importa los módulos necesarios: `requests`, `colorama`, `json`, `ssl`, `socket`, y `datetime`.

### Inicialización de Colorama:

- Inicializa colorama para permitir el uso de colores en la salida de la consola.

### ASCII Art:

- Define una variable `ascii_art` que contiene un arte ASCII que se imprime al inicio del script.

### URLs de Archivos JSON:

- Define las URLs de los archivos JSON que contienen las cabeceras recomendadas y las cabeceras que no deben estar presentes.

### Carga de Cabeceras OWASP:

- Realiza solicitudes HTTP para obtener los archivos JSON y carga las cabeceras recomendadas y las que deben ser eliminadas en diccionarios.

### Función check_headers:

- Toma una URL como argumento.
- Realiza una solicitud HTTP a la URL y obtiene las cabeceras de la respuesta.
- Verifica la presencia de cada cabecera recomendada y proporciona información adicional si alguna está ausente.
- Verifica la ausencia de cabeceras que no deben estar presentes.

### Función check_certificate:

- Toma una URL como argumento.
- Extrae el nombre del host de la URL.
- Intenta establecer una conexión SSL con el host y obtiene el certificado.
- Verifica la validez del certificado y muestra las fechas de validez.
- Maneja varios errores de conexión y SSL.

### Función validate_and_check:

- Toma una URL como argumento.
- Asegura que la URL comience con `http://` o `https://`.
- Genera una lista de URLs a verificar, incluyendo versiones con y sin `www`.
- Para cada URL, verifica el certificado y luego las cabeceras.

### Ejecución Principal:

- Solicita al usuario que ingrese una URL.
- Llama a la función `validate_and_check` con la URL proporcionada.
