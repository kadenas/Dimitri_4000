# Dimitri 4000

Monitor sencillo para verificar servidores SIP mediante mensajes OPTIONS e
INVITE. Incluye una interfaz de terminal basada en `curses` para realizar
pruebas de latencia y observar el estado de la conexión.

## Uso

### Prueba rápida de OPTIONS

```bash
python app.py <host> [puerto]
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
