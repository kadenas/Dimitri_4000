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
python app.py [host] [puerto]
python app.py --dst <host> --dst-port <puerto> --protocol udp --count 1
```

Opciones principales:

- `-c/--config`: ruta al archivo de configuración.
- `-n/--name`: nombre del destino dentro del archivo de configuración.
- `--dst`: host destino (alternativa a los posicionales).
- `--dst-port`: puerto destino (por defecto 5060).
- `--protocol`: `udp` o `tcp` (TCP no implementado).
- `--interval`: segundos entre envíos.
- `--timeout`: tiempo de espera de respuesta.
- `--bind-ip`: IP de origen (opcional).
- `--src-port`: puerto UDP de origen (0 para efímero).
- `--count`: número de OPTIONS a enviar (`0` para infinito).

## Ejemplos

### Prueba rápida de OPTIONS

```bash
python app.py 10.1.72.188 5060 --count 2
```
El log muestra el puerto efímero real desde el que se envía, por ejemplo:

```
2024-03-05 12:00:00,000 - sip_manager - INFO - Enviando OPTIONS a 10.1.72.188:5060 sent-by=10.1.64.18:53123
```

Para fijar el puerto de origen:

```bash
python app.py 10.1.72.188 5060 --src-port 5062
```

### Ejemplo con flags modernos

```bash
python app.py --dst 10.1.72.188 --dst-port 5060 --protocol udp --count 2 --interval 0.5 --timeout 2
```
El comando anterior crea/actualiza `dimitri_stats.csv` con las métricas.

### CSeq incremental

```bash
python app.py 10.1.72.188 5060 --count 3 --cseq-start 7
```

Este comando envía tres OPTIONS con CSeq 7, 8 y 9.

### Ejemplo con flags modernos

```bash
python app.py --dst 10.1.72.188 --dst-port 5060 --protocol udp --count 2 --interval 0.5 --timeout 2
```
El comando anterior crea/actualiza `dimitri_stats.csv` con las métricas.

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

### Modo servicio y respuesta a OPTIONS

Para mantener el proceso activo enviando OPTIONS periódicos y respondiendo a
peticiones entrantes, utiliza `--service` junto con `--reply-options`. Si se
encuentra detrás de NAT, asegúrate de exponer `--src-port 5060`.

Ejemplo 1: “faro” completo:

```bash
python app.py --service --reply-options --src-port 5060 --dst 10.1.72.188 --dst-port 5060 --interval 1 --cseq-start 1
```

Ejemplo 2: solo responder:

```bash
  python app.py --service --reply-options --src-port 5060
  ```

### UAS básico para INVITE

El modo UAS responde a `INVITE` entrantes con `100/180/200` y gestiona el
diálogo hasta `ACK/BYE`. Se habilita con `--uas`, lo que implica `--service`.

Ejemplo 1: UAS que también responde a OPTIONS:

```bash
python app.py --uas --reply-options --bind-ip 10.1.64.18 --src-port 5060
```

Ejemplo 2: UAS con timbres y BYE automático tras 10 s:

```bash
python app.py --uas --uas-ring-delay 1 --uas-answer-after 3 --uas-talk-time 10 --bind-ip 10.1.64.18 --src-port 5062
```

Limitaciones: no soporta autenticación, PRACK ni Record-Route.

El `Contact` del `200 OK` incluye siempre el puerto local real. El cliente
envía el `ACK` al host:puerto indicado en ese `Contact` (si no trae puerto, se
usa el puerto origen del `200 OK`).

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

## Llamadas de prueba (INVITE)

Permite establecer una llamada básica enviando INVITE/ACK/BYE o cancelar si no
hay respuesta.

Llamada completa y colgar a los 5 s:

```bash
python app.py --invite --to sip:10.1.72.188 --dst 10.1.72.188 --dst-port 5060 --src-port 5062 --talk-time 5 --ring-timeout 15
```

Intento con CANCEL por no respuesta:

```bash
python app.py --invite --to sip:10.1.72.188 --dst 10.1.72.188 --ring-timeout 5 --talk-time 0
```

### Finalización de la llamada

Existen tres modos para terminar una llamada del lado UAC:

1. `--talk-time N` (por defecto 5) – tras enviar `ACK` espera *N* segundos y
   envía `BYE` propio.
2. `--talk-time 0` sin `--wait-bye` – la llamada finaliza inmediatamente tras
   el `ACK`, sin enviar `BYE`.
3. `--wait-bye` – se mantiene la sesión activa hasta recibir un `BYE` remoto.
   Con `--max-call-time N` se limita la espera; si se supera, se envía un `BYE`
   propio y se cierra la llamada.

En cualquiera de los casos, `Ctrl+C` durante la espera envía un único `BYE` y
termina limpiamente con `result=aborted`.

### Timeout y CANCEL

Cuando se supera `--ring-timeout` se envía un `CANCEL` y se espera hasta 5 s
por las respuestas finales. Si llega `487 Request Terminated` se responde con
`ACK` y la llamada termina con `result=canceled`. Si no llega nada en ese plazo,
se finaliza con `result=canceled-timeout`.

Limitaciones actuales: no soporta autenticación, PRACK ni manejo de SDP
de respuesta.

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

## RTP básico

Soporte RTP sencillo está disponible para los códecs PCMU/PCMA. No incluye
SRTP ni ICE, por lo que en redes con NAT se requiere abrir puertos o habilitar
`--symmetric-rtp`.

Ejemplo de bucle local (UAS/UAC en la misma máquina):

```bash
UAS: python app.py --uas --bind-ip 192.168.0.137 --src-port 5062 \
     --uas-answer-after 1 --rtp-port 40000 --codec pcmu --rtp-stats-every 1
UAC: python app.py --invite --dst 192.168.0.137 --dst-port 5062 --src-port 5060 \
     --rtp-port 42000 --codec pcmu --rtp-tone 1000 --rtp-stats-every 1
```

Se puede guardar el audio recibido en un WAV con `--rtp-save-wav`.

Limitaciones: no hay SRTP, ICE ni cancelación de eco; la detección de NAT es
básica.
