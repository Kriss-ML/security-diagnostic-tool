import dns.resolver as dr
import ipaddress
from ipwhois import IPWhois
import whois
from datetime import datetime
import logging 

""" En este modulo extrae y procesa el diagnostico  retornando en una Lista de Diccionarios
    -SPF
    -DMARC
    -MX 
    -DKim
    -Ip infraestructura CDM/WAF
    -la funcion diagnostico_seguridad(Dominio) <--- se envia el dominio y retorna la La lista de Diccionarios
    que contienen:
    -Categoria
    -Estado
    -Riesgo
    -Descripcion 
    -Puntaje

"""
logging.basicConfig(filename="Diagnostico_Ip.log", level=logging.INFO,
                    format= "%(asctime)s - %(levelname)s- %(message)s")
logger = logging.getLogger(__name__)

#_____________________EXTRACCIÓN DE REGISTROS DNS__________________________
"""Esta funcion esta echa para recibir 2 argumentos el dominio y el tipo de registro que se quiere 
extraer ejemplo (dominio "MX") como vi que se extraen de la misma manera lo hice asi para reciclar codigo,
lo extraido lo convierte en lista y lo retorna.
"""
def extraer_registros_dns(dominio, tipo_registro: str) -> list:
    try:
        
        registros = dr.resolve(dominio, tipo_registro)
        return [r.to_text() for r in registros]
    except Exception as e:
        logger.warning(f"Error al intentar extraer registro Tipo: {tipo_registro} [ {e} ]") 
        return None  

def obtener_dmarc_policy(dominio: str):
    registros_txt = extraer_registros_dns(f"_dmarc.{dominio}", "TXT")
    for reg in registros_txt:
        reg = reg.strip('"').lower()
        if reg.startswith("v=dmarc1"):
            partes = reg.split(";")
            for p in partes:
                p = p.strip()
                if p.startswith("p="):
                    return p.split("=")[1]
    return None

#_____________________EXTRAER SPF________________________________________
""" Esta Funcion se procesa si existe SPF o no. 
    recibe  La lista extraida por la funcion extraer_registros_dns(dominio,tipo_registro <----este caso registros "TXT")
"""

def existe_spf(registros_txt: list) -> bool:
    for txt in registros_txt:
        if "v=spf1" in txt.lower():
            return True
    return False

#_____________________EXTRAER DKIM______________________________________
def extraer_dkim(dominio: str) -> list:
    
    """
    Extrae registros DKIM usando únicamente una lista de selectores comunes.
    Retorna una lista de tuplas: (selector, subdominio, registro TXT)

    """
    selectores_comunes = [
        "default", "s1", "mail", "google", "selector1",
        "dkim1", "m1", "s1024", "s2048", "smtp",
        "key1", "email", "default1", "dkim", "google1",
        "selector2", "s2", "mail1", "m2", "s1024a"
    ]
    
    base = dominio
    encontrados = []
    for selector in selectores_comunes:
        nombre = f"{selector}._domainkey.{base}"
        try:
            respuestas = dr.resolve(nombre, "TXT")
            for r in respuestas:
                texto = r.to_text().strip('"')
                if "v=dkim1" in texto.lower():
                    encontrados.append((selector, base, texto))
        except (dr.NXDOMAIN, dr.NoAnswer, dr.LifetimeTimeout):
            continue
        except Exception as e:
            continue
    return encontrados

"""
    En esta funcion retorna la existencia de DMARC se extrae y si la encuentra retorna True
"""
def existe_dmarc(dominio: str) -> bool:
    try:
        respuestas = dr.resolve(f"_dmarc.{dominio}", "TXT")
        for r in respuestas:
            if "v=dmarc1" in r.to_text().lower():
                return True
        return False
    except Exception:
        return False

#_____________________DETECTAR INFRAESTRUCTURA / WAF______________________
""" En esta funcion  Comprueba si la IP pertenece a:
    - CDN/WAF conocido (Cloudflare, Akamai, etc.)
    - Grandes infraestructuras propias (Google, Facebook, Amazon)
    recibe como argumento la IP ,  hace la comparacion de los rangos retorna True y 
    si se cumple la funcion Any 
    aqui averiguando y para evitar el error de antes de Ip no encontrada en el rango 
    utilizo la herramienta 
    ipwhois 
"""

def ip_pertenece_a_cdn(ip: str) -> bool:
    
    CDN_RANGOS = [
        ipaddress.ip_network("104.16.0.0/13"),  
        ipaddress.ip_network("172.64.0.0/13"),  
        ipaddress.ip_network("131.0.72.0/22"), 
    ]

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logger.error(f"ERROR ip invalida{ip}")
        return False

    # Revisar rangos CDN conocidos
    if any(ip_obj in rango for rango in CDN_RANGOS):
        
        return True

    # Revisar AS/Organization real de la IP
    try:
        objeto = IPWhois(ip)
        ip_info = objeto.lookup_rdap(retry_count=1) #<--parametro : si falla solo lo intentara una vez mas 
         #↓↓↓ aqui es del diccionario Network extraene el valor de la clave "nombre" 
        organizacion = ip_info.get("network", {}).get("name", "").lower()#<------Aqui se extra el nombre de la organizacion 
        asn_organizacion = ip_info.get("asn_description", "").lower() 
        proveedores = ["google", "facebook", "meta", "amazon"] #<-----Lista de Proveedores 
        #↓↓↓ si alguno se cumple la funcion any en organizacion o ans_organizacion en la lista de proveedores returna True
        
        if any(x in organizacion for x in proveedores) or any(x in asn_organizacion for x in proveedores):
            logger.info(f"la {ip} pertenece a un provedor identificado: {organizacion}")
            return True
    except Exception:
        pass
        logger.warning(f"No se pudo consultar RDAP para ip: {ip}")
    logger.info("La ip no coicide CDN/WAF")    
    return False

def obtener_spf_policy(dominio: str):
    registros_txt = extraer_registros_dns(dominio, "TXT")
    for reg in registros_txt:
        reg = reg.strip('"').lower()
        if reg.startswith("v=spf1"):
            partes = reg.split(" ")
            return partes
    return None

def obtener_info_ip(ip):
    
    """
    Devuelve el ASN y la organización propietaria de la IP.
    Si ocurre un error, devuelve (None, None)

    """
    try:
        obj = IPWhois(ip)
        resultado = obj.lookup_rdap(depth=1)
        org = resultado.get('network', {}).get('name', 'Desconocida')
        asn = resultado.get('asn', 'Desconocido')
        return asn, org
    except Exception as e:
        logger.info(f"No fue posible acceder a la Organizacion y al ASN de la IP: {ip}")
        
        return None, None

#_____________________DIAGNÓSTICO WHOIS__________________________________
def diagnostico_whois(dominio: str) -> dict:
    logger.info("Diagnostico whois iniciado... ")
    try:
        info = whois.whois(dominio) #<----esto retorna un "Diccionario "(<class 'whois.parser.WhoisCom'>)  
        riesgo = "BAJO"
        descripcion = []
        puntaje=10 

        exp_date = getattr(info, "expiration_date", None)
        if exp_date:
            logger.info(f"Fecha de Expiracion Obteniada")
            if isinstance(exp_date, list):
                exp_date = exp_date[0]
            if exp_date.tzinfo:
                exp_date = exp_date.replace(tzinfo=None)
            if exp_date < datetime.now(): #<---si ya expiro
                riesgo = "ALTO"
                puntaje= 60
                descripcion.append(f"Dominio expirado el {exp_date.date()}")
                logger.warning(f"La fecha del Dominio ah explirado: {exp_date} hoy es:{datetime.now}")
            else:
                descripcion.append(f"Dominio válido hasta {exp_date.date()}")
                logger.info(f"Dominio valido expira hasta el {exp_date} ")
        else:
            riesgo = "MEDIO"
            puntaje= 15 
            descripcion.append("Fecha de expiración no disponible")
            logger.warning("No se fue posible acceder la fecha de Expiracion del dominio")

        org = getattr(info, "org", None)
        if org:
            if org=="REDACTED FOR PRIVACY":
                descripcion.append("Propietario Oculto (Privado).")
            else:
                descripcion.append(f"Propietario encontrado: {org}")
                logger.info(f"Organizacion encontrada {org}")
        else:
            if riesgo !="ALTO": 
                riesgo = "MEDIO"
                puntaje = max(puntaje, 15)
                descripcion.append("Propietario del dominio no disponible")

        registrar = getattr(info, "registrar", None)
        if registrar:
            descripcion.append(f"Registrador: {registrar}")
            logger.info(f"Registrador encontrado: {registrar}")
        emails = getattr(info, "emails", None)
            
        if emails:
            descripcion.append(f"Emails de contacto: {emails}")
            logger.info(f"Emails Encontrados: {emails}")

        dnssec = getattr(info, "dnssec", None)

        if dnssec:
            if dnssec == "unsigned":
                if riesgo != "ALTO":
                    riesgo = "MEDIO"
                    puntaje = max(puntaje, 25)
                descripcion.append("DNSSEC no habilitado: respuestas DNS sin firma criptográfica")
                logger.info(f"[DNSSEC]: {dnssec} / No habilitado")

            elif dnssec == "signed":
                descripcion.append("DNSSEC habilitado: el dominio protege la integridad de sus respuestas DNS")
                logger.info(f"[DNSSEC]: {dnssec} / Habilitado")

            elif dnssec == "bogus":
                riesgo = "ALTO"
                puntaje = max(puntaje, 50)
                descripcion.append("DNSSEC incorrecto: firma inválida o fallo de validación")
                logger.warning(f"[DNSSEC]: {dnssec} / Error de validación")

            elif dnssec == "signedDelegation":
                if riesgo != "ALTO":
                    riesgo = "MEDIO"
                    puntaje = max(puntaje, 20)
                descripcion.append(
                    "DNSSEC parcialmente habilitado: la delegación está firmada pero la zona puede no estar completamente protegida"
                )
                logger.info(f"[DNSSEC]: {dnssec} / Delegación firmada")
            
            elif dnssec == "indeterminate":
                if riesgo != "ALTO":
                    riesgo = "MEDIO"
                    puntaje = max(puntaje, 25)
                descripcion.append("DNSSEC indeterminado: no se pudo verificar el estado")
                logger.warning(f"[DNSSEC]: {dnssec} / Estado desconocido")

            else:
                if riesgo != "ALTO":
                    riesgo = "MEDIO"
                    puntaje = max(puntaje, 25)
                descripcion.append(f"DNSSEC estado desconocido: {dnssec}")
                logger.warning(f"[DNSSEC]: {dnssec} / No reconocido")

        else:
            if riesgo != "ALTO":
                riesgo = "MEDIO"
                puntaje = max(puntaje, 25)
            descripcion.append("DNSSEC no disponible: no se pudo obtener información")
            logger.warning("[DNSSEC]: Sin datos")
            
        return {
            "categoria": "Información del dominio",
            "estado": "Información de Whois obtenida",
            "riesgo": riesgo,
            "descripcion": "; ".join(descripcion),
            "puntaje": puntaje
        }
    except Exception as e:
        logger.error("Error al intentar acceder al Registro Whois")
        return {
            "categoria": "Información del dominio",
            "estado": "No disponible",
            "riesgo": "ALTO",
            "descripcion": f"No se pudo obtener información de Whois: {e}",
            "puntaje": 0
        }

#_____________________DIAGNÓSTICO DE SEGURIDAD COMPLETO___________________

def diagnostico_Seguridad(dominio: str) -> list:
    informe = []
    # --- Diagnóstico Correo electrónico unificado ---
    registros_txt = extraer_registros_dns(dominio, "TXT")
    if not registros_txt:
        raise ValueError("No se han encontrado registros")

#____DIAGNOSTICO_SPF___________________________________________________
    spf_existe = existe_spf(registros_txt)
    spf_policy = obtener_spf_policy(dominio)
    if not spf_existe:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "SPF no configurado",
            "riesgo": "ALTO",
            "descripcion": "El dominio no tiene registro SPF, permitiendo que cualquier servidor envíe correos en su nombre.",
            "puntaje": 50
        })
    elif spf_policy is None:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "SPF presente pero no interpretable",
            "riesgo": "MEDIO",
            "descripcion": "Existe un registro SPF, pero no se pudo analizar correctamente.",
            "puntaje": 35
        })
    elif "-all" in spf_policy:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "SPF estricto (-all)",
            "riesgo": "BAJO",
            "descripcion": "Solo los servidores autorizados pueden enviar correos. SPF correctamente configurado.",
            "puntaje": 5
        })

    elif "~all" in spf_policy:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "SPF blando (~all)",
            "riesgo": "MEDIO",
            "descripcion": "Los correos no autorizados se aceptan pero se marcan como sospechosos.",
            "puntaje": 25
        })
    elif "+all" in spf_policy or "all" in spf_policy:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "SPF permisivo (+all)",
            "riesgo": "ALTO",
            "descripcion": "Cualquier servidor puede enviar correos en nombre del dominio. Configuración insegura.",
            "puntaje": 60
        })

#____DIAGNOSTICO_DMARC__________________________________________
    dmarc_existe = existe_dmarc(dominio)
    politica = obtener_dmarc_policy(dominio)
    #---NO existe DMARC
    if not dmarc_existe:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DMARC no configurado",
            "riesgo": "ALTO",
            "descripcion": "El dominio no tiene registro DMARC, lo que permite suplantación de identidad por correo.",
            "puntaje": 90
        })

    #---DMARC existe pero política no identificada
    elif politica is None:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DMARC presente pero política indeterminada",
            "riesgo": "MEDIO",
            "descripcion": "Existe un registro DMARC pero no se pudo determinar la política aplicada.",
            "puntaje": 60
        })

    elif politica == "none":
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DMARC en modo monitoreo (none)",
            "riesgo": "MEDIO",
            "descripcion": "DMARC existe pero no aplica acciones contra correos fraudulentos.",
            "puntaje": 45
        })

    elif politica == "quarantine":
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DMARC en modo cuarentena (quarantine)",
            "riesgo": "BAJO",
            "descripcion": "Los correos no autenticados se envían a spam.",
            "puntaje": 20
        })

    elif politica == "reject":
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DMARC estricto (reject)",
            "riesgo": "MUY BAJO",
            "descripcion": "Los correos fraudulentos son rechazados automáticamente.",
            "puntaje": 5
        })
 
# ____________________ DIAGNÓSTICO MX ____________________

    registros_mx = extraer_registros_dns(dominio, "MX")    # No existen registros MX
    if not registros_mx :
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "MX no configurado",
            "riesgo": "MEDIO",
            "descripcion": "El dominio no dispone de registros MX, por lo que no puede recibir correos electrónicos.",
            "puntaje": 30
        })
    else:
        proveedores_conocidos = [
            "google.com",
            "outlook.com",
            "hotmail.com",
            "protection.outlook.com",
            "yahoodns.net",
            "zoho.com"
        ]

        mx_protegido = False
        mx_ip_directa = False
        detalles_mx = []

        for mx in registros_mx:
            mx = mx.lower().strip()
            detalles_mx.append(mx) #<------punto al final indica FQDN (Fully Qualified Domain Name) segun que mx.
        
            # Proveedor conocido
            if any(prov in mx for prov in proveedores_conocidos): #<----Comprueba si esta protegido 
                mx_protegido = True

            # MX apuntando directamente a IP
            try:
                ipaddress.ip_address(mx)
                mx_ip_directa = True
            except ValueError:
                pass
                

        # MX apunta a IP directa
        if mx_ip_directa:
            informe.append({
                "categoria": "Correo electrónico",
                "estado": "MX apunta a IP directa",
                "riesgo": "ALTO",
                "descripcion": f"Se detectó MX apuntando a IP directa. Detalles MX: {', '.join(detalles_mx)}",
                "puntaje": 45
            })

        # MX gestionado por proveedor conocido
        elif mx_protegido:
            informe.append({
                "categoria": "Correo electrónico",
                "estado": "MX gestionado por proveedor conocido",
                "riesgo": "BAJO",
                "descripcion": f"Proveedor de correo reconocido. Detalles MX: {', '.join(detalles_mx)}",
                "puntaje": 5
            })

        # MX personalizado
        else:
            informe.append({
                "categoria": "Correo electrónico",
                "estado": "MX personalizado",
                "riesgo": "MEDIO",
                "descripcion": f"MX propios o poco conocidos. Detalles MX: {', '.join(detalles_mx)}",
                "puntaje": 20
            })

# ____DIAGNOSTICO_DKIM________________________________________________
    dkim_encontrados = extraer_dkim(dominio)
    if dkim_encontrados:
        selector_detectado, subdominio, registro = dkim_encontrados[0]

        tipo_clave = "desconocido"
        if "k=rsa" in registro:
            tipo_clave = "RSA"

        longitud = "desconocida"
        if "p=" in registro:
            longitud = ">=1024 bits"

        informe.append({
            "categoria": "Correo electrónico",
            "estado": f"DKIM configurado (selector: {selector_detectado})",
            "riesgo": "BAJO",
            "descripcion": (
                f"Se detectó un registro DKIM automáticamente usando un selector común: "
                f"{selector_detectado}._domainkey.{subdominio}. "
                f"Tipo de clave: {tipo_clave}. "
                f"Longitud estimada: {longitud}."
            ),
            "puntaje": 5
        })

    else:
        informe.append({
            "categoria": "Correo electrónico",
            "estado": "DKIM no detectado automáticamente",
            "riesgo": "BAJO",
            "descripcion": (
                "No se pudo detectar un registro DKIM usando selectores comunes. "
                "Esto no implica ausencia de DKIM, sino que puede requerir el selector específico."
            ),
            "puntaje": 8
        })


#_____________________DIAGNÓSTICO INFRAESTRUCTURA WEB (A)_____________________

    registros_a = extraer_registros_dns(dominio, "A")
    #no hay registros A
    if not registros_a:
        informe.append({
            "categoria": "Infraestructura Web",
            "estado": "Sin registros A",
            "riesgo": "INFORMATIVO",
            "descripcion": "No se encontraron direcciones IP públicas asociadas al dominio.",
            "puntaje": 0 
        })

    else:
        detalles_ips = []
        alguna_protegida = False

        for ip in registros_a:
            pertenece_cdn = ip_pertenece_a_cdn(ip)
            asn, org = obtener_info_ip(ip)

            if pertenece_cdn:
                alguna_protegida = True
                estado_ip = "Protegida por CDN/WAF"

            else:
                estado_ip = f"Expuesta (ASN: {asn} pertenece a {org})"

            detalles_ips.append(f"{ip} -> {estado_ip}")

        #ninguna IP protegida
        if not alguna_protegida:
            informe.append({
                "categoria": "Infraestructura Web",
                "estado": "Servidor expuesto directamente a Internet",
                "riesgo": "MEDIO",
                "descripcion": "Las IPs no pertenecen a ningún CDN/WAF conocido. "
                            "El servidor responde directamente a Internet. "
                            "Detalles: " + " | ".join(detalles_ips),
                "puntaje": 40
            })

        #al menos una IP protegida...
        else:
            informe.append({
                "categoria": "Infraestructura Web",
                "estado": "Protegida parcialmente por CDN/WAF",
                "riesgo": "BAJO",
                "descripcion": "Al menos una IP pertenece a un CDN/WAF o infraestructura protegida. "
                            "Detalles: " + " | ".join(detalles_ips),
                "puntaje": 15
            })

    informe.append(diagnostico_whois(dominio))
    return informe 
         