"""Contenido textual único del informe pericial (UNE 197010:2015).

Centraliza todo el texto narrativo que antes estaba duplicado, palabra por
palabra, entre `generar_pdf` y `generar_docx`. Cualquier corrección legal o de
redacción se hace ahora una sola vez aquí, que lo tenía repetido en report_generator.
"""

# --- 1. Declaración de imparcialidad (art. 335.2 LEC) ---
DECLARACION_INTRO = (
    "D./Dña. {nombre}, con titulación de {titulacion} y número de colegiado "
    "{colegiado}, declara bajo juramento o promesa, conforme a lo establecido en "
    "el artículo 335.2 de la Ley de Enjuiciamiento Civil:"
)

DECLARACIONES_IMPARCIALIDAD = [
    "Que ha actuado y actuará con la mayor objetividad posible, tomando en "
    "consideración tanto lo que pueda favorecer como lo que sea susceptible de "
    "causar perjuicio a cualquiera de las partes.",
    "Que conoce las sanciones penales en las que podría incurrir si incumpliera "
    "su deber como perito.",
    "Que no se halla incurso en ninguna de las causas de tacha previstas en el "
    "artículo 343 de la Ley de Enjuiciamiento Civil.",
    "Que no tiene relación de parentesco, dependencia, amistad íntima o enemistad "
    "con ninguna de las partes intervinientes.",
    "Que carece de interés directo o indirecto en el asunto objeto del informe.",
]

# --- 2. Resumen ejecutivo ---
RESUMEN_EJECUTIVO = (
    "El presente informe documenta el análisis forense de triaje realizado sobre "
    "la evidencia digital identificada, con el objetivo de obtener una primera "
    "caracterización del sistema y de la actividad relevante registrada en el mismo. "
    "El análisis se ha llevado a cabo de forma automatizada mediante la herramienta "
    "Triaje Forense Automatizado desarrollada en el marco de este TFM."
)

# --- 3. Objeto del encargo (valor por defecto) ---
OBJETO_DEFECTO = (
    "Realizar un análisis forense automatizado de triaje sobre la evidencia digital "
    "aportada, con el fin de extraer y documentar los artefactos del sistema operativo "
    "más relevantes para la investigación: identificación del sistema, cuentas de "
    "usuario, historial de dispositivos conectados, actividad de ejecución de "
    "programas, mecanismos de persistencia, conexiones de red, actividad del usuario, "
    "navegación web y estado de seguridad del equipo."
)

# --- 4. Antecedentes (valor por defecto) ---
ANTECEDENTES_DEFECTO = (
    "Se ha recibido la evidencia digital identificada a continuación para la "
    "realización del presente análisis de triaje forense."
)

# --- 5. Fuentes de información ---
FUENTES_INTRO = (
    "La única fuente de información empleada en este análisis es la imagen forense "
    "que se identifica a continuación:"
)

# --- 6. Análisis (introducción) ---
ANALISIS_INTRO = (
    "El análisis se ha realizado de forma automatizada combinando el uso de las "
    "librerías pytsk3 (acceso al sistema de archivos mediante The Sleuth Kit), "
    "pyewf (lectura de imágenes EnCase), python-registry (parseo de hives de "
    "registro de Windows) y python-evtx (análisis del log de eventos). A "
    "continuación se exponen, ordenados temáticamente, los resultados obtenidos."
)

EVENTO_1102_NOTA = (
    "Evento 1102 detectado: el borrado del log de auditoría es un indicador típico "
    "de manipulación intencional del sistema con el fin de ocultar actividad."
)

# --- 7. Conclusiones ---
CONCLUSIONES_INTRO = (
    "Conforme a los resultados anteriormente expuestos, este perito llega a las "
    "siguientes conclusiones a partir del análisis automatizado:"
)

CONCLUSIONES_TRIAJE = (
    "Cabe destacar que este informe constituye un análisis de triaje, orientado a "
    "obtener una primera caracterización rápida de la evidencia. Los hallazgos aquí "
    "expuestos deben ser ampliados con un análisis forense en profundidad que "
    "confirme, amplíe o matice cada uno de los puntos relevantes."
)

CIERRE_PERICIAL = (
    "Esta es mi fiel y técnica Información Pericial, que someto al más ilustrado "
    "dictamen de Su Señoría en {lugar_firma}, a {fecha_emision}, y para que ello "
    "conste, firmo a día de hoy."
)

# --- 8. Anexos ---
ANEXOS_INTRO = (
    "Como anexo al presente informe se entrega la propia herramienta automatizada "
    "utilizada para el análisis (Triaje Forense Automatizado), cuya interfaz gráfica "
    "permite consultar de forma interactiva todos los datos extraídos en mayor nivel "
    "de detalle del que se reproduce en este documento."
)

GLOSARIO = [
    ("Hive", "Archivo del registro de Windows que almacena la configuración del sistema."),
    ("Prefetch", "Mecanismo de Windows para acelerar el arranque de ejecutables, que "
                 "conserva metadatos de las últimas ejecuciones."),
    ("UserAssist", "Clave del registro que almacena un contador de ejecuciones GUI por usuario."),
    ("Amcache", "Hive que registra metadatos de ejecutables que han corrido en el sistema."),
    ("Shimcache", "Caché de compatibilidad de aplicaciones, también usada para inferir ejecuciones."),
    ("MFT", "Master File Table — tabla principal del sistema de archivos NTFS."),
    ("USBSTOR", "Clave del registro SYSTEM que enumera dispositivos USB de almacenamiento."),
    ("Triaje", "Análisis preliminar rápido que prioriza qué evidencias requieren profundización."),
]

# --- Índice ---
INDICE_ITEMS = [
    "1. Declaración de imparcialidad y juramento",
    "2. Resumen ejecutivo",
    "3. Objeto del encargo",
    "4. Antecedentes",
    "5. Fuentes de información",
    "6. Análisis",
    "    6.1 Identificación del sistema",
    "    6.2 Cuentas de usuario",
    "    6.3 Aplicaciones instaladas",
    "    6.4 Historial de dispositivos USB",
    "    6.5 Actividad de ejecución",
    "    6.6 Persistencia",
    "    6.7 Actividad de red",
    "    6.8 Actividad del usuario",
    "    6.9 Navegación web y búsquedas",
    "    6.10 Estado de seguridad",
    "7. Conclusiones",
    "8. Anexos",
]
