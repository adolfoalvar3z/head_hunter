try:
    import requests
    from colorama import init, Fore, Style
    import json
    import ssl
    import socket
    from datetime import datetime, timezone
except ModuleNotFoundError as e:
    print(f"Error: {e}. Please install the required module using 'pip install {e.name}'")
    exit(1)

########################################
### AUTOR: Adolfo Alvarez - Ninj470
### FECHA: 2024-12-04
### VERSION: 1.0
########################################

# ASCII art
ascii_art = rf"""{Fore.GREEN}
__                    _
| |__   ___  __ _  __| | ___ _ __
| '_ \ / _ \/ _` |/ _` |/ _ \ '__|
| | | |  __/ (_| | (_| |  __/ |
|_| |_|\___|\__,_|\__,_|\___|_|____
| |__  _   _ _ __ | |_ ___ _ |_____|
| '_ \| | | | '_ \| __/ _ \ '__|
| | | | |_| | | | | ||  __/ |
|_| |_|\__,_|_| |_|\__\___|_|

Revisión de Cabeceras basadas en recomendaciones Owasp
https://owasp.org/www-project-secure-headers/
MEJORES PRACTICAS:
https://owasp.org/www-project-secure-headers/index.html#div-bestpractices

"""
# Inicializa colorama
init(autoreset=True)

print(ascii_art)

# URLs de los archivos JSON
headers_add_url = "https://owasp.org/www-project-secure-headers/ci/headers_add.json"
headers_remove_url = "https://owasp.org/www-project-secure-headers/ci/headers_remove.json"

# Cargar los encabezados recomendados desde el archivo JSON
headers_json = requests.get(headers_add_url).text
OWASP_HEADERS = {header["name"]: header["value"] for header in json.loads(headers_json)["headers"]}

# Cargar los encabezados que no deben estar presentes desde el archivo JSON
headers_remove_json = requests.get(headers_remove_url).text
HEADERS_REMOVE = json.loads(headers_remove_json)["headers"]

def check_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        print(f"{Fore.CYAN}Revisando headers de seguridad para {url}\n")
        for header, proposed_value in OWASP_HEADERS.items():
            if header in headers:
                if header == "X-Powered-By":
                    print(f"{Fore.RED}[-] {header} está presente con valor: {headers[header]}. El X-Powered-By encabezado describe las tecnologías que utiliza el servidor web. Esta información expone al servidor a los atacantes. Con la información de este encabezado, los atacantes pueden encontrar vulnerabilidades con mayor facilidad")
                else:
                    print(f"{Fore.GREEN}[+] {header} está presente con valor: {headers[header]}")
            else:
                if header == "X-Powered-By":
                    print(f"{Fore.GREEN}[+] {header} está ausente")
                else:
                    print(f"{Fore.RED}[-] {header} está ausente")
                    if header == "Strict-Transport-Security":
                        print(f"{Fore.CYAN}Strict-Transport-Security: {Fore.RESET}Asegura que el navegador solo se comunique con el servidor a través de HTTPS, previniendo ataques de intermediarios.")
                    elif header == "X-Frame-Options":
                        print(f"{Fore.CYAN}X-Frame-Options: {Fore.RESET}Protege contra ataques de clickjacking al controlar si una página puede ser mostrada en un frame.")
                    elif header == "X-Content-Type-Options":
                        print(f"{Fore.CYAN}X-Content-Type-Options: {Fore.RESET}Evita que el navegador interprete archivos como un tipo diferente al declarado, previniendo ataques de tipo MIME.")
                    elif header == "Content-Security-Policy":
                        print(f"{Fore.CYAN}Content-Security-Policy: {Fore.RESET}Ayuda a prevenir ataques de inyección de contenido, como XSS, controlando los recursos que el navegador puede cargar.")
                    elif header == "X-Permitted-Cross-Domain-Policies":
                        print(f"{Fore.CYAN}X-Permitted-Cross-Domain-Policies: {Fore.RESET}Restringe las políticas de dominio cruzado permitidas.")
                    elif header == "Referrer-Policy":
                        print(f"{Fore.CYAN}Referrer-Policy: {Fore.RESET}Controla la información de referencia que se envía con las solicitudes, protegiendo la privacidad del usuario.")
                    elif header == "Clear-Site-Data":
                        print(f"{Fore.CYAN}Clear-Site-Data: {Fore.RESET}Permite a los sitios limpiar datos almacenados en el navegador.")
                    elif header == "Cross-Origin-Embedder-Policy":
                        print(f"{Fore.CYAN}Cross-Origin-Embedder-Policy: {Fore.RESET}Requiere que los recursos incrustados sean de la misma procedencia.")
                    elif header == "Cross-Origin-Opener-Policy":
                        print(f"{Fore.CYAN}Cross-Origin-Opener-Policy: {Fore.RESET}Asegura que las ventanas abiertas sean de la misma procedencia.")
                    elif header == "Cross-Origin-Resource-Policy":
                        print(f"{Fore.CYAN}Cross-Origin-Resource-Policy: {Fore.RESET}Restringe cómo los recursos pueden ser compartidos entre orígenes.")
                    elif header == "Permissions-Policy":
                        print(f"{Fore.CYAN}Permissions-Policy: {Fore.RESET}Permite o deniega el uso de ciertas características del navegador, como geolocalización o cámara.")
                    elif header == "Cache-Control":
                        print(f"{Fore.CYAN}Cache-Control: {Fore.RESET}Controla cómo, cuándo y dónde se puede almacenar en caché una respuesta.")
                    elif header == "Content-Type":
                        print(f"{Fore.CYAN}Content-Type: {Fore.RESET}Controla cómo, cuándo y dónde se puede almacenar en caché una respuesta.")

        print(f"\n{Fore.CYAN}Revisando headers que no deben estar presentes para {url}\n")
        for header in HEADERS_REMOVE:
            if header in headers:
                print(f"{Fore.RED}[-] {header} está presente y NO debería estarlo")
            else:
                print(f"{Fore.GREEN}[+] {header} está ausente, como se esperaba")
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] No se puede establecer una conexión con {url}")

def check_certificate(url):
    hostname = url.replace("https://", "").replace("http://", "").split('/')[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:  # Added timeout
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"\n{Fore.CYAN}Revisando certificado de seguridad para {url}\n")
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                print(f"{Fore.CYAN}Válido desde: {not_before}")
                print(f"{Fore.CYAN}Válido hasta: {not_after}")
                if datetime.now(timezone.utc) < not_after:
                    print(f"{Fore.GREEN}[+] El certificado está vigente.")
                else:
                    print(f"{Fore.RED}[-] El certificado ha expirado.")
    except ssl.SSLError:
        print(f"{Fore.RED}[-] El sitio no tiene un certificado SSL válido. Intentando conectar a través de HTTP.")
        return False
    except ConnectionRefusedError:
        print(f"{Fore.RED}[-] No se puede establecer una conexión ya que el equipo de destino denegó expresamente dicha conexión.")
        return False
    except TimeoutError:
        print(f"{Fore.RED}[-] La conexión a {url} ha expirado. El servidor no respondió a tiempo.")
        return False
    except socket.gaierror:
        print(f"{Fore.RED}[-] No se puede resolver el nombre de host {hostname}. Verifique la URL e intente nuevamente.")
        return False
    return True

def validate_and_check(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    urls_to_check = [url]
    if "://" in url:
        protocol, rest = url.split("://", 1)
        if not rest.startswith("www."):
            urls_to_check.append(f"{protocol}://www.{rest}")
        else:
            urls_to_check.append(f"{protocol}://{rest[4:]}")
    else:
        if not url.startswith("www."):
            urls_to_check.append(f"www.{url}")
        else:
            urls_to_check.append(url[4:])

    for url in urls_to_check:
        print(f"{Fore.YELLOW}[!] Probando URL: {url}")
        if not check_certificate(url):
            url = url.replace("https://", "http://")
            print(f"{Fore.YELLOW}[!] Conectando a través de HTTP: {url}")
        check_headers(url)

if __name__ == "__main__":
    url = input("Ingresa la URL del sitio web a revisar: ")
    validate_and_check(url)
