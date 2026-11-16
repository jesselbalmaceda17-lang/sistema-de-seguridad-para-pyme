"""Session-scoped Streamlit controls; acquisition never runs in the render thread."""
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from seguridad_pymes.database import PersistenceError
from seguridad_pymes.monitor_capture import list_interfaces
from seguridad_pymes.monitoring import CaptureManager, CaptureConfig
from seguridad_pymes.monitor_rules import RuleConfig
from seguridad_pymes.pcap_reader import CaptureError


@st.cache_resource(scope='session', on_release=lambda manager: manager.shutdown(), show_spinner=False)
def _manager(root):
    return CaptureManager(root)


@st.cache_data(ttl=5, show_spinner=False)
def _interfaces():
    return list_interfaces()


STATES = {'idle': 'Sin monitoreo', 'starting': 'Iniciando captura', 'capturing': 'Monitoreo activo',
          'stopping': 'Deteniendo y guardando', 'stopped': 'Monitoreo detenido',
          'completed': 'Monitoreo finalizado por límite', 'failed': 'Monitoreo con error', 'interrupted': 'Interrumpido'}
REVIEW = {'Pendiente': 'pending', 'Revisada como confirmada': 'confirmed', 'Falso positivo': 'false_positive'}


@st.fragment(run_every=1)
def render_network_monitor():
    st.header('Monitoreo de red')
    st.caption('Detección: reglas transparentes sobre tráfico observado. No utiliza Random Forest ni confirma ataques.')
    st.write('Solo se observa el tráfico accesible desde la interfaz seleccionada. Ver toda una LAN puede requerir un puerto espejo, TAP u otra infraestructura autorizada. Loopback observa comunicaciones locales de este equipo.')
    root = str(Path(os.environ.get('SIPYMES_MONITOR_DIR', 'data/monitoring')).resolve())
    manager = _manager(root)
    manager.heartbeat()
    active = manager.active
    state = manager.snapshot()
    interfaces = []
    try:
        interfaces = _interfaces()
    except CaptureError as error:
        st.error(str(error))
    selected = st.selectbox('Interfaz autorizada', options=interfaces,
                           format_func=lambda item: item.description, disabled=active or not interfaces,
                           index=0 if interfaces else None, key='monitor_interface')
    authorized = st.checkbox('Estoy autorizado para monitorear esta interfaz y conservar los paquetes observados.',
                             key='monitor_authorized', disabled=active)
    with st.expander('Configuración y límites del monitoreo'):
        st.caption('Configuraciones operativas de partida; los umbrales no están científicamente validados para todas las PYMES. Al cambiar un valor se aplica a la próxima sesión.')
        duration = st.number_input('Duración máxima (segundos)', 5, 3600, 300, key='monitor_duration', disabled=active)
        memory = st.number_input('Memoria máxima de captura (MiB)', 64, 2048, 256, key='monitor_memory', disabled=active)
        storage = st.number_input('Presupuesto total de historial y capturas (MiB)', 16, 2048, 128, key='monitor_storage', disabled=active)
        window = st.number_input('Ventana de observación (segundos)', 1, 300, 30, key='monitor_window', disabled=active)
        syn = st.number_input('Umbral de paquetes SYN sin ACK por origen', 1, 1000000, 100, key='monitor_syn', disabled=active)
        ports = st.number_input('Umbral de puertos destino distintos en SYN por origen', 1, 65536, 30, key='monitor_ports', disabled=active)
        volume = st.number_input('Umbral de volumen IPv4 por origen (KiB)', 1, 1048576, 10240, key='monitor_volume', disabled=active)
        st.caption('Captura pasiva, sin modo promiscuo: solo IPv4 TCP/UDP. Se excluye el puerto del servidor Streamlit para evitar medir su propio canal de control. No se analiza IPv6, fragmentación ni payload de aplicación. SYN incluye retransmisiones; ausencia de respuesta no se etiqueta como fallo. Se conservan PCAPNG locales, que pueden contener información sensible.')
        st.caption('Máximo 100.000 paquetes, 2.000 flujos activos, 10.000 segmentos; colas y ventanas acotadas. Sin señal de la pestaña durante 20 s se detiene la captura. El presupuesto incluye sesiones anteriores; no se eliminan automáticamente.')
    first, second = st.columns(2)
    if first.button('Iniciar monitoreo', disabled=active or selected is None or not authorized, key='monitor_start', type='primary'):
        try:
            manager.start(selected.identifier, CaptureConfig(duration_seconds=duration, capture_memory_mib=memory,
                storage_mib=storage, excluded_ports=(int(st.get_option('server.port')),), rules=RuleConfig(window_seconds=window, syn_packets=syn,
                                                     destination_ports=ports, ipv4_bytes=volume * 1024)), authorized=authorized)
        except (CaptureError, PersistenceError, OSError, ValueError) as error:
            st.error(f'No se pudo iniciar el monitoreo: {error}')
    if second.button('Detener monitoreo', disabled=not active, key='monitor_stop'):
        manager.stop()
    state = manager.snapshot()
    st.write(f"Estado: **{STATES.get(state['status'], state['status'])}**")
    if state['reason']:
        st.warning(state['reason'])
    if state.get('session_id'):
        if state.get('source_kind') != 'live':
            st.warning('Reproducción de laboratorio; estos datos no son una captura en vivo.')
        a, b, c, d = st.columns(4)
        a.metric('Paquetes observados', state['packets_seen'])
        b.metric('Conexiones observadas', state['connections_observed'])
        c.metric('Segmentos guardados', state['flows_persisted'])
        d.metric('Alertas por reglas guardadas', state['alerts_persisted'])
        st.caption(f"Paquetes admitidos: {state['packets_accepted']} · excluidos: {state['packets_rejected']}. Conexiones cuenta tuplas de direcciones, puertos y protocolo; una conexión puede producir varios segmentos temporales.")
        if state['partial']:
            st.error('Sesión parcial: revise errores y cobertura. No interprete la ausencia de alertas como ausencia de actividad sospechosa.')
        if not state['packets_seen']:
            st.info('Todavía no se observó tráfico IPv4 TCP/UDP compatible. Compruebe la conexión y la interfaz seleccionada; esto no demuestra que toda la red esté inactiva.')
        if state.get('recent_flows'):
            with st.expander('Conexiones procesadas recientemente'):
                st.dataframe(pd.DataFrame(state['recent_flows']), hide_index=True)
        with st.expander('Calidad y recursos de esta sesión'):
            st.json({key: value for key, value in state.items() if key not in {'recent_flows'}})
    else:
        st.info('Seleccione una interfaz y confirme su autorización para iniciar. Paquetes: 0 · conexiones: 0.')
    try:
        alerts = manager.store.alerts()
        sessions = manager.store.sessions()
        st.subheader('Alertas e historial del monitoreo')
        if alerts:
            display = pd.DataFrame([{'fecha UTC': row['detected_at'], 'severidad': row['severity'],
                'origen': row['source'], 'regla': row['rule'], 'motivo': row['message'],
                'revisión': row['review_state'], 'método': 'Reglas transparentes'} for row in alerts])
            st.dataframe(display, hide_index=True)
            by_id = {row['event_id']: row for row in alerts}
            chosen_id = st.selectbox('Alerta de monitoreo para revisar', options=list(by_id),
                format_func=lambda identifier: f"{by_id[identifier]['rule']} · {by_id[identifier]['source']} · {by_id[identifier]['detected_at']}", key='monitor_review_id')
            chosen = by_id[chosen_id]
            st.write(chosen['message'])
            evidence = json.loads(chosen['evidence_json'])
            evidence['review_state'] = chosen['review_state']
            st.caption(f"Observado: {evidence['observed']} · umbral: {evidence['threshold']} · ventana: {evidence['window_seconds']} s · severidad: {chosen['severity']}.")
            with st.expander('Evidencia cuantitativa de la alerta'):
                st.json(evidence)
            labels = list(REVIEW)
            current = next(label for label in labels if REVIEW[label] == chosen['review_state'])
            # Include event/state in the key so selecting another alert resets the editor correctly.
            review = st.selectbox('Revisión manual del monitoreo', labels, index=labels.index(current),
                                  key=f"monitor_review_state_{chosen['event_id']}_{chosen['review_state']}")
            if st.button('Guardar revisión de monitoreo', key='monitor_review_save'):
                manager.store.review(chosen['event_id'], REVIEW[review])
                st.success('Revisión guardada. No modifica la observación ni confirma técnicamente un ataque.')
        else:
            st.info('No hay alertas por reglas registradas. Esto no certifica que el tráfico sea seguro.')
        if sessions:
            with st.expander('Historial de sesiones de monitoreo'):
                st.dataframe(pd.DataFrame([{'inicio UTC': row['started_at'], 'interfaz': row['interface_name'],
                    'estado': STATES.get(row['status'], row['status']), 'tipo': row['source_kind'],
                    'motivo de cierre': row['reason']} for row in sessions]), hide_index=True)
                st.caption('Se consultan las 20 sesiones y 100 alertas más recientes. Son independientes del historial CSV.')
    except (PersistenceError, ValueError) as error:
        st.error(f'No se pudo consultar o revisar el historial de monitoreo: {error}')
