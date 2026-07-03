# Sigma Detection Rules

Conjunto de reglas de detección en formato [Sigma](https://github.com/SigmaHQ/sigma) para 4 técnicas
comunes de MITRE ATT&CK, cubriendo tanto entornos Linux como Windows. Cada regla incluye su
justificación, logs de ejemplo para validarla y su conversión a una query real de Elasticsearch/Kibana.

El objetivo de este repositorio es mostrar el ciclo completo de **detection engineering**: desde
identificar una técnica de ataque hasta tener una regla desplegable en un SIEM real, no solo un
ejercicio teórico.

## ¿Por qué Sigma?

Sigma es un formato de reglas de detección agnóstico al SIEM: se escribe una vez y se convierte al
lenguaje de consulta de Splunk, Elastic, QRadar, Microsoft Sentinel, etc. Es el estándar de facto en
la industria para compartir y versionar lógica de detección (usado por SOC teams, CERTs y proyectos
como SigmaHQ).

## Estructura del repositorio

```
sigma-detection-rules/
├── rules/                          # Reglas Sigma (.yml)
│   ├── linux_ssh_bruteforce.yml
│   ├── linux_cron_persistence.yml
│   ├── windows_registry_run_key_persistence.yml
│   └── windows_powershell_encoded_command.yml
├── sample-logs/                    # Logs de ejemplo para validar cada regla
├── converted-elastic/              # Reglas ya convertidas a Lucene (Elastic/Kibana)
└── README.md
```

## Reglas incluidas

| Regla | Técnica MITRE ATT&CK | Plataforma | Severidad |
|---|---|---|---|
| Fuerza bruta SSH | [T1110](https://attack.mitre.org/techniques/T1110/) - Brute Force | Linux | Medium / High (con correlación) |
| Persistencia vía cron | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) - Scheduled Task/Job: Cron | Linux | Medium |
| Persistencia vía Registry Run Key | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) - Boot or Logon Autostart Execution | Windows | Medium |
| PowerShell con comando codificado | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) / [T1027](https://attack.mitre.org/techniques/T1027/) | Windows | High |

## Cómo probar las reglas

1. Instalar `sigma-cli` y el backend de Elasticsearch:
   ```bash
   pip install sigma-cli pysigma-backend-elasticsearch
   ```

2. Convertir una regla a query de Elastic (Lucene):
   ```bash
   sigma convert -t lucene -p ecs_windows rules/windows_powershell_encoded_command.yml
   ```
   Para las reglas Linux, que usan campos genéricos, se convierten sin pipeline:
   ```bash
   sigma convert -t lucene --without-pipeline rules/linux_cron_persistence.yml
   ```

3. La carpeta `converted-elastic/` ya contiene el resultado de cada conversión, listo para pegar en
   Kibana → Security → Rules → Custom query.

4. Los logs de `sample-logs/` están diseñados para disparar cada regla: contienen tanto eventos
   maliciosos como legítimos (falsos positivos evitados), para poder verificar que la regla distingue
   correctamente entre ambos.

## Nota sobre la regla de fuerza bruta SSH

Esta regla usa el formato de **correlación** de Sigma (introducido en Sigma v2): una regla base
detecta el evento individual (login fallido) y una segunda regla eleva la severidad cuando hay 5 o
más eventos del mismo `source.ip` en 5 minutos. Este patrón evita alertar por un simple error de
usuario y solo dispara ante un patrón real de ataque automatizado.

La parte de correlación no es convertible a una query Lucene estática (requiere estado y ventana
temporal), así que en un despliegue real se implementaría como una **Threshold Rule** nativa de
Kibana Security usando la query base como filtro.

## Próximos pasos (roadmap)

- [ ] Añadir reglas para exfiltración vía DNS tunneling
- [ ] Añadir pipeline de CI (GitHub Actions) que valide sintácticamente cada PR con `sigma check`
- [ ] Exportar también a formato Splunk (SPL) para comparar cobertura multi-SIEM

## Autor

Raúl Sineiro Domínguez — Máster en Ciberseguridad, Campus Internacional de Ciberseguridad
[github.com/raulsineiro](https://github.com/raulsineiro)
