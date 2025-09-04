# Dimitri 4000

Monitor sencillo para verificar servidores SIP mediante mensajes OPTIONS e
INVITE. Incluye una interfaz de terminal basada en `curses` para realizar
pruebas de latencia y observar el estado de la conexión.

## Instalación en Ubuntu

```bash
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://example.com/Dimitri_4000.git
cd Dimitri_4000
# opcional: python3 -m venv venv && source venv/bin/activate
```

No se requieren dependencias adicionales, el proyecto usa únicamente la
biblioteca estándar de Python.

### Permisos para puertos <1024

El puerto SIP por defecto es el **5060**, que está por debajo del límite de
puertos privilegiados. Para poder enlazarlo se puede:

* Ejecutar el script con `sudo`.
* Otorgar la capacidad `CAP_NET_BIND_SERVICE` al intérprete de Python:

  ```bash
  sudo setcap 'cap_net_bind_service=+ep' $(which python3)
  ```

* Usar la opción `--port` para elegir un puerto mayor a 1024.

## Configuración y parámetros

### Archivo de configuración

Define destinos en `config.yaml` (JSON válido). Cada destino acepta los
siguientes campos:

- `ip`: dirección del servidor remoto.
- `port`: puerto SIP (por defecto 5060).
- `protocol`: `UDP` o `TCP`.
- `interval`: segundos entre solicitudes repetidas.
- `timeout`: tiempo de espera por respuesta.
- `retries`: reintentos ante errores o timeouts.

### Parámetros de ejecución

```
python app.py <host> [puerto]
```

Opciones principales:

- `-c/--config`: ruta al archivo de configuración.
- `-n/--name`: nombre del destino dentro del archivo de configuración.
- `--port`: puerto alternativo para el destino seleccionado.
- `--count`: número de OPTIONS a enviar (`0` para infinito).

## Ejemplos

### Prueba rápida de OPTIONS

```bash
python app.py <host> [puerto]
```

### Usar archivo de configuración

Define destinos en `config.yaml` (JSON válido):

```yaml
{
  "destinations": {
    "local": {"ip": "127.0.0.1", "port": 5060, "protocol": "UDP", "interval": 5},
    "backup": {"ip": "192.0.2.10", "port": 5080, "protocol": "TCP", "interval": 10}
  }
}
```

Selecciona un destino y envía OPTIONS periódicos:

```bash
python app.py -c config.yaml -n local --count 0
```

Para usar un puerto alternativo:

```bash
python app.py -c config.yaml -n local --port 5070
```

### Interfaz interactiva

```bash
python -m ui.main [host] [puerto]
```

Atajos dentro de la interfaz:

- `m` – Inicia o detiene la monitorización periódica de OPTIONS.
- `i` – Envía un INVITE con cabeceras personalizadas separadas por `;`.
- `q` – Sale de la aplicación.

La pantalla muestra la latencia de las respuestas, contadores de éxito y fallo,
un log de las últimas acciones y un indicador en color verde o rojo según el
resultado del último OPTIONS.

### Monitorización desde script

```bash
python - <<'PY'
from sip_manager import SIPManager
m = SIPManager('127.0.0.1', interval=5)
m.send_request('OPTIONS', repeat=3)
print(m.get_stats('OPTIONS'))
PY
```

Este fragmento realiza tres OPTIONS y muestra estadísticas básicas.

### Lanzar una llamada INVITE desde script

```bash
python - <<'PY'
from sip_manager import SIPManager
m = SIPManager('192.0.2.10')
response, latency = m.send_request('INVITE')
print('Respuesta:', response)
print('Latencia:', latency)
PY
```

Este ejemplo crea un `SIPManager`, envía un INVITE y muestra la respuesta y el
tiempo empleado.
